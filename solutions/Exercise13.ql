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

  /**
   * Returns the integer value of the expected type specified for the element at `input_index`
   */
  int getExpectedInputType(int input_index) {
    result = this.getArgument(input_index).getValue().toInt()
  }
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
    guard.ensuresEq(dest, other, 0, block, true) and
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
 * `input_types` parameter to a subsequent use in a GuardCondition.
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
 * A flow-state representing the state of dynamic input type validation.
 */
newtype TTypeValidationState =
  TTypeUnvalidatedState() or
  TTypeValidatedState(TypeValidationCall call)

/**
 * A class describing the type validation state
 */
class TypeValidationState extends TTypeValidationState {
  string toString() {
    this = TTypeUnvalidatedState() and result = "unvalidated"
    or
    this = TTypeValidatedState(_) and result = "validated"
  }
}

/**
 * A flow-state in which the type of a dynamic input array has *not* been validated.
 */
class TypeUnvalidatedState extends TypeValidationState, TTypeUnvalidatedState { }

/**
 * A flow-state in which the type of a dynamic input array has been validated.
 */
class TypeValidatedState extends TypeValidationState, TTypeValidatedState { }

/**
 * A global data-flow configuration tracking flow from an entrypoint's
 * `input` parameter to a subsequent `ArrayExpr` access.
 */
module InputToAccessConfig implements DataFlow::StateConfigSig {
  class FlowState = TTypeValidationState;

  predicate isSource(DataFlow::Node source, FlowState state) {
    exists(EntrypointFunction ep | ep.getInputParameter() = source.asParameter()) and
    state instanceof TypeUnvalidatedState
  }

  predicate isSink(DataFlow::Node sink, FlowState state) {
    exists(DynamicInputAccess access |
      sink.asExpr() = access.getArrayBase() and
      access.isTypeNotValidated() and
      state instanceof TypeUnvalidatedState
    )
  }

  predicate isAdditionalFlowStep(DataFlow::Node node1, DataFlow::Node node2) {
    exists(FunctionCall fc |
      fc.getTarget().hasName("lock_input") and
      fc.getArgument(0) = node1.asExpr() and
      fc = node2.asExpr()
    )
  }

  predicate isAdditionalFlowStep(
    DataFlow::Node node1, FlowState state1, DataFlow::Node node2, FlowState state2
  ) {
    // leave this predicate as-is for this workshop step
    none()
  }

  predicate isBarrier(DataFlow::Node node, FlowState state) {
    // leave this predicate as-is for this workshop step
    none()
  }
}

module InputToAccess = DataFlow::MakeWithState<InputToAccessConfig>;

import InputToAccess::PathGraph

from InputToAccess::PathNode source, InputToAccess::PathNode sink
where InputToAccess::hasFlowPath(source, sink)
select sink, source, sink,
  "Access to dynamic input array with missing or mismatched type validation."
