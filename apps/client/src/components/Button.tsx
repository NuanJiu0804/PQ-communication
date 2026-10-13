import type { ButtonHTMLAttributes } from "react";

interface ButtonProps extends ButtonHTMLAttributes<HTMLButtonElement> {
  variant?: "primary" | "ghost";
  loading?: boolean;
}

export function Button({
  variant = "primary",
  loading = false,
  disabled,
  children,
  className,
  ...rest
}: ButtonProps) {
  const classes = ["btn", `btn-${variant}`];
  if (className) classes.push(className);

  return (
    <button className={classes.join(" ")} disabled={disabled || loading} {...rest}>
      {loading ? <span className="btn-spinner" aria-hidden /> : null}
      <span className="btn-label">{children}</span>
    </button>
  );
}
