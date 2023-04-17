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
    guardEnsuresEqUnordered(dest, other, guard, block, true)
  )
}

from DynamicInputAccess access
where not typeValidationGuard(_, _, _, access.getBasicBlock())
select access, "Access to dynamic input array without type validation."
