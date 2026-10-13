import type { InputHTMLAttributes } from "react";

interface TextFieldProps extends InputHTMLAttributes<HTMLInputElement> {
  label: string;
  mono?: boolean;
  error?: string;
}

export function TextField({ label, mono, error, id, name, className, ...rest }: TextFieldProps) {
  const inputId = id ?? name;
  const classes = ["field-input"];
  if (mono) classes.push("mono");
  if (error) classes.push("has-error");
  if (className) classes.push(className);

  return (
    <label className="field" htmlFor={inputId}>
      <span className="field-label">{label}</span>
      <input id={inputId} name={name} className={classes.join(" ")} {...rest} />
      {error ? <span className="field-error">{error}</span> : null}
    </label>
  );
}
