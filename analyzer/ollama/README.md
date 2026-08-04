# Analyzer model

The analyzer talks to any OpenAI-compatible chat-completions endpoint. This
directory builds the Ollama model the project is tuned and benchmarked against.

## Build

From the repository root:

```bash
ollama create gemma4:e4b-it-qat-16k -f analyzer/ollama/Modelfile
```

That is the analyzer's default `AI_MODEL`, so no configuration change is needed
after building. Ollama pulls the `gemma4:e4b-it-qat` base automatically if it is
not already present.

The weights and quantization are upstream [`gemma4:e4b-it-qat`](https://ollama.com/library/gemma4:e4b-it-qat)
exactly as published. Only runtime parameters differ, and the `-16k` tag suffix
records what. Keeping a separate tag means `ollama pull gemma4:e4b-it-qat` cannot
silently overwrite these settings.

## Why the stock tag is not enough

Ollama does not size the context window to the model's maximum. It applies
`OLLAMA_CONTEXT_LENGTH`, or its own default, both far below the 131072 tokens
this model supports. Measured on 2026-08-04, a stock install loaded it with a
4096-token window.

Exceeding that window raises no error. Ollama drops the overflow and the model
answers from what remains. The same ~14,700-token prompt sent to both tags:

| Model | `prompt_tokens` reported | Answer |
| --- | --- | --- |
| `gemma4:e4b-it-qat` | 2,051 | Wrong, and confident |
| `gemma4:e4b-it-qat-16k` | 14,742 | Correct |

Nothing in the HTTP response distinguishes a truncated call from a complete one,
so a false-positive verdict reached without the evidence would be published as
though it were genuine.

Setting `num_ctx` per request does not help. The OpenAI-compatible endpoint
ignores it, whether passed at the top level or inside `options`; the window is
fixed when the model loads. That is why this has to be a Modelfile.

## Context budget

Largest prompts the analyzer can emit under the default character caps, measured
rather than estimated:

| Prompt | Tokens | Governing setting |
| --- | --- | --- |
| Enrichment | ~2,150 | `ANALYSIS_FINDING_EVIDENCE_MAX_CHARS=6000` |
| Adjudication | ~2,650 | evidence, enrichment description, evidence brief |
| Report summary | ~4,120 | `ANALYSIS_REPORT_INPUT_MAX_CHARS=24000` |

The report prompt alone exceeds a stock 4096-token window.

`num_ctx` is pinned to 16384, roughly four times the largest measured prompt.
Dense minified HTML tokenizes at about 2.55 characters per token, well below the
common 4.0 rule of thumb, so raising either character cap consumes the window
faster than a character count suggests. Re-measure before increasing them.

## Accuracy

Scored against the 30-case labelled corpus in [`../benchmark/`](../benchmark/),
15 genuine findings and 15 spurious ones across all ten proof types:

| Metric | Value |
| --- | --- |
| Precision | 1.000 |
| Recall | 0.867 |
| F1 | 0.929 |
| Genuine findings discarded | 0 of 15 |

Verdicts were stable across three repeated runs of the primary corpus, with no
case changing verdict. `temperature` is pinned low for that reproducibility;
raising it reintroduces variance between runs on identical evidence.

## Using a different model

Any endpoint that reliably returns JSON matching the analyzer's Pydantic schemas
will work. Two cautions from testing:

- Confirm the context window covers the prompt sizes above. Silent truncation is
  the failure mode, not an error, and `prompt_tokens` in the response is the way
  to check it.
- A security-specialised model is not automatically better. `Foundation-Sec-8B-Instruct`
  scored F1 0.640 against this corpus and discarded two genuine findings, because
  its categorical axis answers contradicted its own verdicts.

Re-run the benchmark before switching:

```bash
cd analyzer && python -m benchmark.run_benchmark --variant brief --corpus all --model <name>
```
