import cpp
import semmle.code.cpp.dataflow.new.DataFlow
import semmle.code.cpp.controlflow.Guards

int dyn_input_type_mem() { result = 1 }

int dyn_input_type_val() { result = 2 }

predicate typeValidationCallMatchesUse(TypeValidationCall call, DynamicInputAccess use) {
  // replace this
  none()
}

/**
 * An access of a dynamic input array (of type `dyn_input_t`)
 */
class DynamicInputAccess extends ArrayExpr {
  DynamicInputAccess() {
    this.getArrayBase().getType().(DerivedType).getBaseType().getName() = "dyn_input_t"
  }

  predicate isTypeNotValidated() {
    // replace this and include mismatched validation
    none()
  }
}

/**
 * A call to `DYN_INPUT_TYPE`
 */
class TypeValidationCall extends FunctionCall {
  TypeValidationCall() { this.getTarget().hasName("DYN_INPUT_TYPE") }

  int getExpectedInputType(int input_index) {
    // replace this
    none()
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

from DynamicInputAccess access
// replace this
where none()
select access
