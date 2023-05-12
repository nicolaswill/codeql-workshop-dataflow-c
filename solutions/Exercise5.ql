/**
 * @id cpp/check-type-before-use
 * @name Check type before use
 * @kind path-problem
 */

import cpp
import semmle.code.cpp.dataflow.new.DataFlow
import semmle.code.cpp.controlflow.Guards

/**
 * An access of a dynamic input array (of type `dyn_input_t`)
 */
class DynamicInputAccess extends ArrayExpr {
  DynamicInputAccess() {
    this.getArrayBase().getType().(DerivedType).getBaseType().getName() = "dyn_input_t"
  }
}

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
    exists(DynamicInputAccess access | sink.asExpr() = access.getArrayBase() and
      not typeValidationGuard(_, _, _, access.getBasicBlock())
    )
  }

  predicate isBarrier(DataFlow::Node node) {
    typeValidationGuard(_, _, _, node.asExpr().getBasicBlock())
  }
}

from InputToAccess::PathNode source, InputToAccess::PathNode sink
where InputToAccess::hasFlowPath(source, sink)
select sink, source, sink, "Access to dynamic input array without type validation."
