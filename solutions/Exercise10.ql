/**
 * @id cpp/check-type-before-use
 * @name Check type before use
 * @kind path-problem
 */

import cpp
import semmle.code.cpp.dataflow.new.DataFlow
import semmle.code.cpp.controlflow.Guards

int dyn_input_type_mem() { result = 1 }

int dyn_input_type_val() { result = 2 }

predicate typeValidationCallMatchesUse(TypeValidationCall call, DynamicInputAccess use) {
  exists(FieldAccess f, int expected |
    expected = call.getExpectedInputType(use.getArrayOffset().getValue().toInt()) and
    f.getQualifier() = use and
    (
      expected = dyn_input_type_mem() and f.getTarget().getName() = "ptr"
      or
      expected = dyn_input_type_val() and f.getTarget().getName() = "val"
    )
  )
}

/**
 * An access of a dynamic input array (of type `dyn_input_t`)
 */
class DynamicInputAccess extends ArrayExpr {
  DynamicInputAccess() {
    this.getArrayBase().getType().(DerivedType).getBaseType().getName() = "dyn_input_t"
  }

  predicate isTypeValidationGuardCompliant(GuardCondition gc, TypeValidationCall call) {
    typeValidationGuardOrIndirect(gc, call, _, this.getBasicBlock()) and
    typeValidationCallMatchesUse(call, this)
  }

  predicate isTypeNotValidated() {
    not typeValidationGuardOrIndirect(_, _, _, this.getBasicBlock())
    or
    exists(TypeValidationCall call |
      typeValidationGuardOrIndirect(_, call, _, this.getBasicBlock()) and
      not typeValidationCallMatchesUse(call, this)
    )
  }
}

/**
 * A call to `DYN_INPUT_TYPE`
 */
class TypeValidationCall extends FunctionCall {
  TypeValidationCall() { this.getTarget().hasName("DYN_INPUT_TYPE") }

  int getExpectedInputType(int input_index) {
    result = this.getArgument(input_index).getValue().toInt()
  }
}

/**
 * Holds if `op1` and `op2` are checked for equality in any order
 * with no distinction between left and right operands of the equality check
 */
predicate guardEnsuresEqUnordered(
  Expr op1, Expr op2, GuardCondition guard, BasicBlock block, boolean areEqual
) {
  guard.ensuresEq(op1, op2, 0, block, areEqual) or
  guard.ensuresEq(op2, op1, 0, block, areEqual)
}

/**
 * Relates a `call` to a `guard`, which uses the result of the call to validate
 * equality of the result of `call` against `other` to guard `block`.
 */
predicate typeValidationGuard(
  GuardCondition guard, TypeValidationCall call, Expr other, BasicBlock block
) {
  exists(Expr dest |
    DataFlow::localExprFlow(call, dest) and
    guardEnsuresEqUnordered(dest, other, guard, block, true) and
    InputTypesToTypeValidation::hasFlowToExpr(other)
  )
}

predicate typeValidationGuardOrIndirect(
  GuardCondition guard, TypeValidationCall call, Expr other, BasicBlock block
) {
  typeValidationGuard(guard, call, other, block) or
  typeValidationGuardOrIndirect(guard, call, other,
    block.getEnclosingFunction().getACallToThisFunction().getBasicBlock())
}

/**
 * A global data-flow configuration tracking flow from an entrypoint's
 *  `input_types` parameter to a subsequent use in a GuardCondition.
 */
module InputTypesToTypeValidation = DataFlow::Make<InputTypesToTypeValidationConfig>;

module InputTypesToTypeValidationConfig implements DataFlow::ConfigSig {
  predicate isSource(DataFlow::Node source) {
    exists(EntrypointFunction f | f.getInputTypesParameter() = source.asParameter())
  }

  predicate isSink(DataFlow::Node sink) {
    // avoid non-monotonic recursion, as `typeValidationGuard` depends on this config
    sink.asExpr() instanceof VariableAccess
  }
}

/**
 * An entrypoint that has a `dyn_array_t[2]` `input` parameter and
 * `input_types` parameter.
 */
class EntrypointFunction extends Function {
  EntrypointFunction() { this.hasName(["EP_copy_mem", "EP_print_val", "EP_write_val_to_mem"]) }

  Parameter getInputParameter() { result = this.getParameter(0) }

  Parameter getInputTypesParameter() { result = this.getParameter(1) }
}

/**
 * A global data-flow configuration tracking flow from an entrypoint's
 * `input` parameter to a subsequent `ArrayExpr` access.
 */
module InputToAccess = DataFlow::Make<InputToAccessConfig>;

import InputToAccess::PathGraph

module InputToAccessConfig implements DataFlow::ConfigSig {
  predicate isSource(DataFlow::Node source) {
    exists(EntrypointFunction ep | ep.getInputParameter() = source.asParameter())
  }

  predicate isSink(DataFlow::Node sink) {
    exists(DynamicInputAccess access |
      sink.asExpr() = access.getArrayBase() and
      access.isTypeNotValidated()
    )
  }

  predicate isBarrier(DataFlow::Node node) {
    exists(FunctionCall fc, DynamicInputAccess access, GuardCondition gc |
      node.asExpr() = fc.getAnArgument() and
      access.isTypeValidationGuardCompliant(gc, _) and
      typeValidationGuard(gc, _, _, node.asExpr().getBasicBlock())
    )
  }
}

from InputToAccess::PathNode source, InputToAccess::PathNode sink
where InputToAccess::hasFlowPath(source, sink)
select sink, source, sink,
  "Access to dynamic input array with missing or mismatched type validation."
