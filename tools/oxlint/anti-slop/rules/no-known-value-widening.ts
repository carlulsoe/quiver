import { defineRule } from "@oxlint/plugins";

import {
  classifyWideningTarget,
  createTypeEnvironment,
  type TypeEnvironment,
  type WideningTarget,
} from "../shared/dictionary-types.ts";
import {
  annotationTarget,
  enclosingFunction,
  functionName,
  hasKnownEvidence,
  hasParentAssertion,
  isDictionaryAccumulatorTarget,
  isEmptyObjectExpression,
  resolveVariable,
  sourceKeyName,
  variableDeclarator,
} from "../shared/known-evidence.ts";

import type { ESTree } from "@oxlint/plugins";

/** Detect sound syntactic cases where a known value is explicitly widened and loses evidence. */
export const noKnownValueWideningRule = defineRule({
  meta: {
    type: "problem",
    docs: {
      description:
        "Disallow syntactically established values from flowing into explicitly broad or anonymous target types that discard useful evidence.",
    },
    messages: {
      widening:
        "The known initializer supplying {{subject}} carries established type evidence, but the explicit {{target}} target type discards it. Preserve inference, use `satisfies`, or introduce/use a named owner contract; parse genuinely external data once at its boundary.",
    },
  },
  createOnce(context) {
    let environment: TypeEnvironment | null = null;

    const reportFlow = (
      expression: ESTree.Expression,
      destination: WideningTarget | null,
      subject: string,
    ) => {
      if (destination === null) return;
      if (isDictionaryAccumulatorTarget(destination) && isEmptyObjectExpression(expression)) {
        return;
      }
      if (!hasKnownEvidence(context.sourceCode, expression)) return;
      context.report({
        node: expression,
        messageId: "widening",
        data: { subject, target: destination.kind },
      });
    };

    const targetFromAnnotation = (annotation: ESTree.TSTypeAnnotation | null | undefined) =>
      environment === null ? null : annotationTarget(annotation, environment);

    return {
      Program(node) {
        environment = createTypeEnvironment(node);
      },
      VariableDeclarator(node) {
        if (node.init === null || node.id.type !== "Identifier") return;
        reportFlow(
          node.init,
          targetFromAnnotation(node.id.typeAnnotation),
          `binding \`${node.id.name}\``,
        );
      },
      PropertyDefinition(node) {
        if (node.value === null) return;
        reportFlow(
          node.value,
          targetFromAnnotation(node.typeAnnotation),
          `property \`${sourceKeyName(context.sourceCode, node.key)}\``,
        );
      },
      AccessorProperty(node) {
        if (node.value === null) return;
        reportFlow(
          node.value,
          targetFromAnnotation(node.typeAnnotation),
          `property \`${sourceKeyName(context.sourceCode, node.key)}\``,
        );
      },
      AssignmentExpression(node) {
        if (node.operator !== "=" || node.left.type !== "Identifier") return;
        const variable = resolveVariable(context.sourceCode, node.left);
        if (variable === null) return;
        const declarator = variableDeclarator(variable);
        if (declarator === null || declarator.id.type !== "Identifier") return;
        reportFlow(
          node.right,
          targetFromAnnotation(declarator.id.typeAnnotation),
          `binding \`${declarator.id.name}\``,
        );
      },
      ReturnStatement(node) {
        if (node.argument === null) return;
        const owner = enclosingFunction(node);
        reportFlow(
          node.argument,
          targetFromAnnotation(owner?.returnType),
          `return value of \`${functionName(context.sourceCode, owner)}\``,
        );
      },
      ArrowFunctionExpression(node) {
        if (node.body.type === "BlockStatement") return;
        reportFlow(
          node.body,
          targetFromAnnotation(node.returnType),
          `return value of \`${functionName(context.sourceCode, node)}\``,
        );
      },
      TSAsExpression(node) {
        if (environment === null || hasParentAssertion(node)) return;
        reportFlow(
          node.expression,
          classifyWideningTarget(node.typeAnnotation, environment),
          "assertion",
        );
      },
      TSTypeAssertion(node) {
        if (environment === null || hasParentAssertion(node)) return;
        reportFlow(
          node.expression,
          classifyWideningTarget(node.typeAnnotation, environment),
          "assertion",
        );
      },
    };
  },
});
