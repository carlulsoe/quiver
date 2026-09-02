import { defineRule } from "@oxlint/plugins";
import type { ESTree } from "@oxlint/plugins";
import { assertedExpression } from "../shared/widened-type-analysis.ts";
import {
  assertionIsNarrower,
  functionBoundary,
  resolvedVariableForIdentifier,
  widenedBinding,
} from "../shared/widened-binding.ts";

/** Detect immutable local bindings that erase a known type and are later asserted back to a narrower type. */
export const noWidenThenAssertRule = defineRule({
  meta: {
    type: "problem",
    docs: {
      description:
        "Disallow local const flows that explicitly widen a known value before asserting the widened binding to a narrower type.",
    },
    messages: {
      widenThenAssert:
        'Binding "{{name}}" erases established type evidence by widening the value, then reconstructs that evidence with a type assertion. Preserve the precise type end-to-end; if the input is genuinely unknown, parse it once at the boundary instead.',
    },
  },
  create(context) {
    const scopes = context.sourceCode.scopeManager.scopes;

    const checkAssertion = (node: ESTree.TSAsExpression | ESTree.TSTypeAssertion) => {
      const expression = assertedExpression(node);
      if (expression.type !== "Identifier") return;

      const variable = resolvedVariableForIdentifier(scopes, expression);
      if (variable === null) return;
      const widened = widenedBinding(variable, scopes);
      if (
        widened === null ||
        node.start <= widened.declaredAt ||
        functionBoundary(node) !== widened.boundary ||
        !assertionIsNarrower(
          context.sourceCode.text,
          widened.broadKind,
          widened.evidence,
          node.typeAnnotation,
        )
      ) {
        return;
      }

      context.report({
        node,
        messageId: "widenThenAssert",
        data: { name: expression.name },
      });
    };

    return {
      TSAsExpression: checkAssertion,
      TSTypeAssertion: checkAssertion,
    };
  },
});
