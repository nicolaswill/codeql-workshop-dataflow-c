import cpp

from ArrayExpr array
where array.getArrayBase().getType().(DerivedType).getBaseType().getName() = "dyn_input_t"
select array, "Access of dynamic input array."
