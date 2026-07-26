// A single ScanConfig field input, driven by a CONFIG_GROUPS field descriptor
// (see data/constants.js). Shared by the new-scan form and the application
// editor, which both edit the same ScanConfig shape.

function coerce(field, raw) {
  if (raw === "") return "";
  if (field.type === "int") {
    const v = parseInt(raw, 10);
    return Number.isNaN(v) ? "" : v;
  }
  if (field.type === "float") {
    const v = parseFloat(raw);
    return Number.isNaN(v) ? "" : v;
  }
  return raw;
}

function configPlaceholder(field) {
  if (field.defaultValue === undefined) return "Default";
  return String(field.defaultValue);
}

function configFieldOutOfRange(field, value) {
  if (value === "" || value === undefined || value === null) return false;
  if (field.type !== "int" && field.type !== "float") return false;
  return value < field.min || value > field.max;
}

// True when every field in every group holds an in-range value.
function configValid(groups, config) {
  return groups.every((group) =>
    group.fields.every(
      (field) => !configFieldOutOfRange(field, config[field.key]),
    ),
  );
}

import Select from "./Select.jsx";

function ConfigField({ field, value, onChange, disabled, idPrefix = "cfg" }) {
  const id = `${idPrefix}-${field.key}`;
  const descriptionId = `${id}-description`;
  const errorId = `${id}-error`;
  const outOfRange = configFieldOutOfRange(field, value);
  const commonProps = {
    id,
    "aria-describedby": outOfRange
      ? `${descriptionId} ${errorId}`
      : descriptionId,
    "aria-invalid": outOfRange || undefined,
    value: value ?? "",
    onChange: (event) =>
      onChange(
        field.key,
        field.type === "select"
          ? event.target.value
          : coerce(field, event.target.value),
      ),
    disabled,
  };
  return (
    <div className='field'>
      <label htmlFor={id}>
        {field.label}
        {field.unit && (
          <span style={{ color: "var(--muted)", marginLeft: 4 }}>
            ({field.unit})
          </span>
        )}
      </label>
      <div className={`control${outOfRange ? " error" : ""}`}>
        {field.type === "select" ? (
          <Select
            value={value ?? ""}
            onChange={(v) => onChange(field.key, v)}
            disabled={disabled}
            options={[
              {value: "", label: field.defaultLabel ? `Default: ${field.defaultLabel}` : "Default"},
              ...field.options.map(([v, l]) => ({value: v, label: l})),
            ]}
          />
        ) : (
          <input
            {...commonProps}
            type={field.type === "text" ? "text" : "number"}
            inputMode={field.type === "int" ? "numeric" : undefined}
            min={field.min}
            max={field.max}
            step={field.step ?? (field.type === "int" ? 1 : "any")}
            maxLength={field.maxLength}
            placeholder={configPlaceholder(field)}
          />
        )}
      </div>
      <p className='field-description' id={descriptionId}>
        {field.description}
      </p>
      {outOfRange && (
        <span className='field-error' id={errorId}>
          Enter a value from {field.min} to {field.max}.
        </span>
      )}
    </div>
  );
}

export default ConfigField;
// eslint-disable-next-line react-refresh/only-export-components
export { coerce, configFieldOutOfRange, configValid };
