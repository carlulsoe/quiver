import type { Locator, Page } from "playwright-core";

export interface FormCandidate {
  index: number;
  submitterIndex: number;
  action: string;
  method: string;
  enctype: string;
  intent: string;
  destructive: boolean;
  purposeful: boolean;
  fields: Array<{ name: string; type: string; value?: string; valueSource: string }>;
  fileFields: string[];
}

export async function inspectForms(page: Page): Promise<FormCandidate[]> {
  return page
    .locator("form")
    .evaluateAll((forms) =>
      forms.map((form, index) => {
        const element = form as HTMLFormElement;
        const baseIntent = [
          element.getAttribute("aria-label"),
          element.getAttribute("name"),
          element.getAttribute("id"),
          element.querySelector("legend")?.textContent,
        ]
          .filter(Boolean)
          .join(" ")
          .trim();
        const submitters = [
          ...element.querySelectorAll<HTMLButtonElement | HTMLInputElement>(
            'button:not([disabled]), input[type="submit"]:not([disabled]), input[type="image"]:not([disabled])',
          ),
        ].filter(
          (control) =>
            control instanceof HTMLInputElement || control.type.toLowerCase() === "submit",
        );
        const submitterIndex = submitters.findIndex((control) => {
          const hint = `${baseIntent} ${control.textContent ?? ""} ${control.value} ${control.formAction}`;
          return (
            /\b(search|filter|find|lookup|login|log\s*in|sign\s*in|authenticate|continue|next|step|verify)\b/i.test(
              hint,
            ) &&
            !/\b(delete|destroy|remove|revoke|logout|sign\s*out|unsubscribe|purchase|pay|checkout|transfer|reset|wipe)\b/i.test(
              hint,
            )
          );
        });
        const selectedSubmitter = submitters[submitterIndex < 0 ? 0 : submitterIndex];
        const effectiveSubmitterIndex = selectedSubmitter
          ? submitters.indexOf(selectedSubmitter)
          : -1;
        const intent =
          [baseIntent, selectedSubmitter?.textContent, selectedSubmitter?.value]
            .filter(Boolean)
            .join(" ")
            .trim() || "form submission";
        const action = selectedSubmitter?.hasAttribute("formaction")
          ? selectedSubmitter.formAction
          : element.action;
        const method =
          (selectedSubmitter?.hasAttribute("formmethod")
            ? selectedSubmitter.formMethod
            : element.method
          ).toUpperCase() || "GET";
        const enctype = selectedSubmitter?.hasAttribute("formenctype")
          ? selectedSubmitter.formEnctype
          : element.enctype;
        const fields = [...element.elements].flatMap((rawControl) => {
          if (
            !(
              rawControl instanceof HTMLInputElement ||
              rawControl instanceof HTMLTextAreaElement ||
              rawControl instanceof HTMLSelectElement
            ) ||
            rawControl.disabled ||
            !rawControl.name
          )
            return [];
          const control = rawControl;
          const type =
            control instanceof HTMLInputElement
              ? control.type.toLowerCase()
              : control instanceof HTMLSelectElement
                ? "select"
                : "textarea";
          if (["submit", "button", "reset", "image", "file", "hidden"].includes(type)) return [];
          let value: string | undefined;
          let valueSource = "semantic";
          if (control.value && type !== "password") {
            value = control.value;
            valueSource = "existing";
          } else if (control instanceof HTMLSelectElement) {
            value = [...control.options].find((option) => !option.disabled && option.value)?.value;
            valueSource = "option";
          } else if (["checkbox", "radio"].includes(type)) {
            value = "true";
            valueSource = "control-type";
          } else {
            const hint =
              `${control.name} ${control.id} ${control.getAttribute("autocomplete") ?? ""} ${control.getAttribute("placeholder") ?? ""}`.toLowerCase();
            if (type === "email" || hint.includes("email")) value = "quiver@example.invalid";
            else if (type === "url" || hint.includes("url")) value = "https://example.invalid/";
            else if (type === "number" || type === "range")
              value = control.getAttribute("min") ?? "1";
            else if (type === "date") value = "2024-01-01";
            else if (type === "datetime-local") value = "2024-01-01T00:00";
            else if (type === "password") value = "quiver-discovery";
            else if (/code|otp|token/.test(hint)) value = "000000";
            else value = control.getAttribute("placeholder") || "quiver";
          }
          return [{ name: control.name, type, value, valueSource }];
        });
        const fileFields = [
          ...element.querySelectorAll<HTMLInputElement>('input[type="file"][name]'),
        ]
          .filter((input) => !input.disabled)
          .map((input) => input.name);
        return {
          index,
          submitterIndex: effectiveSubmitterIndex,
          action,
          method,
          enctype,
          intent,
          destructive:
            /\b(?:delet(?:e|ed|ing|ion)|destroy(?:ed|ing)?|destruction|remov(?:e|ed|ing|al)|revok(?:e|ed|ing|ation)|logout|sign\s*out|unsubscrib(?:e|ed|ing|tion)|purchas(?:e|ed|ing)|pay(?:s|ment|ments|ing|ed)?|checkout|transfer(?:s|red|ring|al)?|reset(?:s|ting)?|wip(?:e|ed|ing)|cancel(?:s|led|ling|lation)?|clos(?:e|ed|ing|ure)|deactivat(?:e|ed|ing|ion)|disabl(?:e|ed|ing|ement)|terminat(?:e|ed|ing|ion)|suspend(?:ed|ing)?|suspension|archiv(?:e|ed|ing|al)|eras(?:e|ed|ing|ure)|purg(?:e|ed|ing))\b/i.test(
              `${intent} ${action}`,
            ),
          purposeful:
            /\b(search|filter|find|lookup|login|log\s*in|sign\s*in|authenticate|continue|next|step|verify)\b/i.test(
              `${intent} ${action}`,
            ),
          fields,
          fileFields,
        };
      }),
    )
    .catch(() => []);
}

export async function fillForm(form: Locator, candidate: FormCandidate): Promise<void> {
  for (const field of candidate.fields) {
    const control = form.locator(`[name=${JSON.stringify(field.name)}]`).first();
    if (["checkbox", "radio"].includes(field.type)) {
      await control.check({ timeout: 500 }).catch(() => undefined);
    } else if (field.type === "select" && field.value !== undefined) {
      await control.selectOption(field.value).catch(() => undefined);
    } else if (field.value !== undefined) {
      await control.fill(field.value, { timeout: 500 }).catch(() => undefined);
    }
  }
}
