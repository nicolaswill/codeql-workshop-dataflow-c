/**
 * @id cpp/check-type-before-use
 * @name Check type before use
 */

import cpp
import semmle.code.cpp.dataflow.new.DataFlow
import semmle.code.cpp.controlflow.Guards

/**
 * A call to `DYN_INPUT_TYPE`
 */
class TypeValidationCall extends FunctionCall {
  TypeValidationCall() { this.getTarget().hasName("DYN_INPUT_TYPE") }
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
class TypeValidatedState extends TypeValidationState, TTypeValidatedState {
  TypeValidationCall call;
  DataFlow::Node node1;
  DataFlow::Node node2;

  TypeValidatedState() { none() }

  /**
   * Returns the call to `DYN_INPUT_TYPE` that validated the type of the dynamic input array.
   */
  TypeValidationCall getCall() { result = call }

  /**
   * Returns the node *from* which the state-changing step occurs
   */
  DataFlow::Node getFstNode() { result = node1 }

  /**
   * Returns the node *to* which the state-changing step occurs
   */
  DataFlow::Node getSndNode() { result = node2 }
}

from TypeValidatedState state, DataFlow::Node preceding
where DataFlow::localFlowStep(preceding, state.getFstNode())
select state.getFstNode(), state.getSndNode(), state.getCall()
