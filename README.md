# CodeQL Workshop — Applied Data-Flow and Control-Flow Analysis for C and C++

## Introduction
In this workshop, we will use a CodeQL to analyse a synthetic example program that receives an `input` array parameter and an `input_types` parameter describing the *expected* type of each element of `input`. The goal of the exercise is to use data-flow, control-flow, and runtime value analysis to identify uses of `input` that are not validated against `input_types`.

This workshop consists of the following three parts, which can be followed in sequence or individually:
1. Basic control-flow and data-flow analysis using local and global data-flow to identify flow from input parameters to unvalidated use. (Beginner)
2. Identifying mismatched type validation, debugging data-flow by using partial flow analysis, and adding missing flow steps. (Intermediate)
3. Further improving the query by using flow-state and runtime value analysis. (Advanced, WIP)

Understanding basic syntactic program analysis and control-flow analysis is a prerequisite to this workshop. If you are not familiar with these concepts, we recommend that you complete [CodeQL Workshop: Syntactical Elements of C/C++](https://github.com/rvermeulen/codeql-workshop-elements-of-syntactical-program-analysis-cpp) and [CodeQL Workshop for C/C++: Control Flow](https://github.com/rvermeulen/codeql-workshop-control-flow-cpp) first. We recommend that you are familiar with the CodeQL language, the CodeQL standard libraries, and data-flow analysis at an elementary level.

As you work through each exercise in this workshop, validate your exercise query by running the associated `exercises-tests` test (under the `Testing` section in the VS Code sidebar). 

You can view an example solution for each exercise in the `solutions` directory.

## Setup instructions
- Install [Visual Studio Code](https://code.visualstudio.com/).
- Install the [CodeQL extension for Visual Studio Code](https://codeql.github.com/docs/codeql-for-visual-studio-code/setting-up-codeql-in-visual-studio-code/).
- Install the latest version of the [CodeQL CLI](https://github.com/github/codeql-cli-binaries/releases).
- Clone this repository:
  ```bash
  git clone https://github.com/kraiouchkine/codeql-workshop-dataflow-c.git
  ```
- Install the CodeQL pack dependencies using the command `CodeQL: Install Pack Dependencies` and select `exercises`, `solutions`, `exercises-tests`, and `solutions-tests` from the list of packs.
- Build the databases using `build-databases.sh` and load the appropriate database for each part of the workshop with the VS Code CodeQL extension. Alternatively, you can download the following prebuilt databases: 
    - [Pre-built CodeQL Database for Part 1](https://drive.google.com/file/d/1halBKf9fQtP2ODepJYFDFO1-6ljt9c9j/view?usp=share_link)
    - [Pre-built CodeQL Database for Part 2](https://drive.google.com/file/d/1MOPTtgAj2QxJ3HhnPqByqFx21onIjnrK/view?usp=share_link)
- :exclamation:Important:exclamation:: Run `initialize-qltests.sh` to initialize the tests. Otherwise, you will not be able to run the QLTests (in `exercises-tests` and `solutions-tests`).

## Example Problem
To illustrate this problem, consider the following simplified example:
```c
#include <stdlib.h>

#define DYN_INPUT_TYPE_NONE 0x0
#define DYN_INPUT_TYPE_MEM 0x1
#define DYN_INPUT_TYPE_VAL 0x2

unsigned int DYN_INPUT_TYPE(unsigned int p0, unsigned int p1) {
  return ((p0) | ((p1) << 4));
}

typedef union dyn_input {
  int val;
  struct {
    void *buf;
    size_t size;
  } ptr;
} dyn_input_t;

void EP_example(dyn_input_t input[2], unsigned int input_types, unsigned int unused) {
  if (input_types = DYN_INPUT_TYPE(DYN_INPUT_TYPE_MEM, DYN_INPUT_TYPE_VAL)) {
    // input[0].ptr.buf is a pointer to a buffer
    // input[0].ptr.size is the size of the buffer
    void *buf = malloc(input[0].ptr.size);
    memcpy(buf, input[0].ptr.buf, input[0].ptr.size); // COMPLIANT
    // ...
    int val = input[0].val; // NON_COMPLIANT - wrong type
    val = input[1].val;     // COMPLIANT
  }
  if (input_types = DYN_INPUT_TYPE(DYN_INPUT_TYPE_NONE, DYN_INPUT_TYPE_VAL)) {
    int val = input[0].val; // NON_COMPLIANT - wrong type
    val = input[1].val;     // COMPLIANT
  }
  input[0].ptr; // NON_COMPLIANT - wrong type
  input[2].ptr; // NON_COMPLIANT - out-of-bounds, wrong type
}
```

The `EP_example` function in this example has three parameters: `input`, `input_types`, and `unused`. `input` is an array of `dyn_input_t` structures, and `input_types` is a `dyn_param_types_t` value, defining the expected types of each element in `input`. The `dyn_input_t` structure is a union of an integer `val` field and a `ptr` field. The `ptr` field is a structure containing a `buf` pointer and a `size` value. 

An `input_types` value describes the type of each element of a `dyn_input_t` array. The `DYN_INPUT_TYPE` macro is used to pack a value from two `DYN_INPUT_TYPE_*` constants (one for each element of the input array). These constants define three possible access rules:
- `DYN_INPUT_TYPE_NONE`: The input is not used and must not be accessed
- `DYN_INPUT_TYPE_MEM`: The input can only be accessed via the `ptr` field
- `DYN_INPUT_TYPE_VAL`: The input can only be accessed via the `val` field

Before use, `input_types` must be validated against an expected value. If no such validation exists, or if the subsequent use does not match the validation, the use may result in undefined behaviour.

## Part 1: Introduction to Data-Flow Analysis by Modeling Missing Type Validation
### Exercise 1
Output all expressions that access a `dyn_input_t` array. Accessing dynamic inputs involves an `ArrayExpr` where the base type of the array type accessed is `dyn_input_t`. These expressions can be thought of as "sinks" for the purpose of data-flow analysis.

<details>
<summary>Hint</summary>
    
    - Use `.getArrayBase().getType().(DerivedType).getBaseType().getName()`

</details>

### Exercise 2
Next, we want to find some cases of dynamic input accesses that are guarded by type validation. Usage of dynamic input is considered unsafe if its type is not validated.

Here are two examples of how validation checks might be implemented:
```c
if (input_types == DYN_INPUT_TYPE(DYN_INPUT_TYPE_MEM, DYN_INPUT_TYPE_VAL)) {
  // access
}
```
```c
unsigned int expected_types = DYN_INPUT_TYPE(DYN_INPUT_TYPE_MEM, DYN_INPUT_TYPE_VAL);
if(expected_types != input_types) {
  return;
}
// access
```

Validation involves a comparison of the `input_types` parameter with a value returned from `DYN_INPUT_TYPE`, where the arguments to that call dictate the expected types of the `dyn_input_t` array.

There are three steps to this exercise:
1. Find all calls to `DYN_INPUT_TYPE`.
2. Restrict the set of `GuardCondition`s to those that have local data-flow from the result of a `DYN_INPUT_TYPE` call.
3. Check if the `GuardCondition` ensures equality against the result of `DYN_INPUT_TYPE` and guards the basic block of the `input` access. Use `GuardCondition::ensuresEq` to model that equality comparison.

Complete the `typeValidationGuard` predicate and output all `input` accesses that are not guarded by a type validation check.

<details>
<summary>Hint</summary>

    - Use DataFlow::localFlow(source, dest) to check if there is flow from the result of `DYN_INPUT_TYPE` to an operand of the `GuardCondition`'s `ensuresEq` check.
    - Use `getBasicBlock` to get the basic block of a `DynamicInputAccess`.

</details>

### Exercise 3
In the previous exercise, we implemented a basic query using local data-flow and control-flow analysis. However, there are false-negatives and false-positives in cases such as the following:
```c
void func_nested(dyn_input_t *input, unsigned int input_types) {
  // Case 1: An access of `input` would result in a false-positive, because
  // input_types is validated in a caller of this function but not here.
}
void func(dyn_input_t *input, unsigned int input_types, int irrelevant_param) {
  if (input_types == DYN_INPUT_TYPE(DYN_INPUT_TYPE_MEM, DYN_INPUT_TYPE_VAL)) {
    func_nested(input, input_types);
  }
  if(irrelevant_param == DYN_INPUT_TYPE(DYN_INPUT_TYPE_MEM, DYN_INPUT_TYPE_VAL)) {
    // Case 2: An access of `input` here would result in a false-negative, because
    // irrelevant_param does not originate from an entrypoint's input_types parameter.
  }
}
```

The solution is global data-flow analysis. Start by modeling the source, i.e. the entrypoints and their parameters. Entrypoints are functions that are not called from anywhere else in the program and match the signature `int(dyn_input_t*, unsigned int)`.

Specifically, these functions are:
- `EP_copy_mem` 
- `EP_print_val`
- `EP_write_val_to_mem`

Output each entrypoint along with its `input` and `input_types` parameters.

<details>
<summary>Hint</summary>

    - Use `Function::hasName(["name1, "name2", ...])` to check if the function has a name matching an entry from a list of strings.
    - Optional: Model these entrypoints heuristically by finding functions with the above specified signature and no calls to the function.

</details>

### Exercise 4
Model the data-flow of `input` and `input_types` from an entrypoint parameter (a source) to a use (a sink). Create two separate global data-flow configurations: one for `input` and one for `input_types` By doing so, we can:
* Ensure that a `typeValidationGuard` validates only `input_types` and not just any value.
* Output paths on which `input` does not have type validation before access.

Start by thinking about and defining the `source` and `sink` for each of the two configurations.

Output all paths from an entrypoint to a dynamic input access that does not have a local type validation check.
<details>
<summary>Hint</summary>

    - The sources for `input` and `input_types` are the relevant `DataFlow::ParameterNode`s of an entrypoint.
    - The sinks for `input` are accesses of `input`.
    - The sinks for `input_types` are should be `other` in the `typeValidationGuard` predicate. However, if you try defining the sink as such, usage of that configuration in the `typeValidationGuard` predicate will result in monotonic recursion.

</details>

We have resolved the false-negatives but not the false-positives in `copy_mem_nested`, which we will resolve in the following exercise. 

#### :exclamation: **Note** :exclamation:<br>
In subsequent exercises, mentions of the "configuration"/"global data-flow config" refer to the `input`/access data-flow config (*not* the `input_types` to type-check configuration).


### Exercise 5
In the previous exercise, we output all paths from an entrypoint to a dynamic input access that do not have a local type validation check. However, each `copy_mem_nested` outputs three paths of which only one is a true positive.

The reason for these false positives lies in the `not typeValidationGuard(_, _, _, access.getBasicBlock())` condition. The `typeValidationGuard` predicate uses local data- and control-flow graphs and thus does not restrict results in functions lower in the call stack than the function performing the type checking. To resolve this false positive, restrict flow through any node in a `BasicBlock` guarded by a type check.

Define an `isBarrier` predicate in the data-flow configuration to block flow through `BasicBlock` already guarded by a type check.

The query should output all `input` accesses with missing type checks without the false-positives from previous exercises.

### Exercise 6
Under construction. Skip this exercise.

## Part 2: Mismatched Type Validation and Debugging Data-Flow to Find Missing Flow Steps
This part of the workshop continues from Part 1 and adds two complicating factors:
1. Cases where type validation exists but does not match the fields subsequently accessed.
2. Missing edges between data-flow nodes that require extra modeling.
  
Up until now, we have only associated the inputs (sources) to their access (sinks) and treated type-checking as a simple guard condition. To expand this query, we no longer want to treat type checking as only a guard condition but rather in relation to the input use. 

It is important not to confuse control- and data-flow here.
  
We rely on the control-flow graph to:
* Verify that the guard condition exists and to identify the subsequent blocks it guards
 
We rely on the data-flow graph to:
* Link `DYN_INPUT_TYPE` results to guard conditions (local data-flow)
* Link `input` parameters from entrypoints to their accesses (global data-flow)
* Link `input_types` parameters from entrypoints to guard conditions (global data-flow)
  
Unlike the previous data-flow configuration, we need to propagate the state of the control guard conditions throughout the data-flow problem. The previous configuration simply defines data-flow nodes guarded by a specified barrier (the `input_types` guard) as guarded nodes, meaning data-flow cannot propagate through them. We now *do* want data-flow to propogate through those nodes, but we also want to note the expected type checked in the guard condition.
  
Since the first part of this workshop covers all cases with *missing* checks, we need to cover the additional cases with *mismatched* checks. 

We can take a step back and rephrase this problem as "finding all parameter accesses without a type-check matching the type accessed."

### Exercise 7
One solution to finding mismatched type checks/accesses is removing the `isBarrier` prediate and instead adding some recursive control-flow-based heuristics. To implement this solution, perform the following steps:
1. Search for a `typeValidationGuard` guarding a dynamic input access.
2. If no such guard exists locally, search backwards transitively from the control node at each `FunctionCall` which calls the function. In other words, perform step 1 transitively for each `FunctionCall`/callee node pair, until a guard condition is found.

Output all dynamic input accesses and each `GuardCondition` that guards it or a guarded `FunctionCall` that calls the function containing the access.

<details>
<summary>Hint</summary>

* Define a new predicate: `typeValidationGuardOrIndirect`
* `typeValidationGuardOrIndirect` should check if exists a `typeValidationGuard` for `block` or `block.getEnclosingFunction().getACallToThisFunction().getBasicBlock()`.
* Relate each input access to a `controllingGuardConditionOrIndirect`.

</details>

Before moving to the next exercise, try to answer the following question:
"Why might this solution produce more inaccurate results than the previous solution with an `isBarrier` predicate?"

<details>
<summary>Answer</summary>

* Unlike global data-flow analysis, which is path sensitive, our control-flow analysis is path-insensitive and does not preserve state in certain cases.
* What if the guard condition occurs in a function that calls another function twice in two branches, with one branch correctly validating the type and the other not?
* Without outputting each (access, guard) pair instead of a path graph, there is no path-sensitive output.
* Part 3 of this workshop explores a solution to this problem using flow-state.

</details>


### Exercise 8
To detect mismatched type validation, extract the type specified for each input in a call to `DYN_INPUT_TYPE` and compare it to the type of access.

| Input Type          | Description                                                       |
|---------------------|-------------------------------------------------------------------|
| DYN_INPUT_TYPE_NONE | The input at this index does not exist and may not be accessed.   |
| DYN_INPUT_TYPE_MEM  | The input at this index may only be accessed via its `ptr` field. |
| DYN_INPUT_TYPE_VAL  | The input at this index may only be accessed via its `val` field. |

Output every access that has a missing type check or a type-check that does not match the type of access.

<details>
<summary>Hint</summary>

* Find a `FieldAccess fa` where `fa.getQualifier()` is an `ArrayExpr` and `fa.getTarget().getName()` is the name of the field accessed.
* Use `.getValue().getInt()` to get the integer value of a `DYN_INPUT_TYPE` argument.

</details>

### Exercise 9
Combine the logic from the previous exercise back into the data-flow configuration so that we have some path-sensitivity and can output specific paths from entry-points to dynamic input accesses that do not have a type check matching the type accessed. You should now see multiple results with flow paths when running the query.

Compare the results from Exercise 8 and Exercise 9; what are the differences, and what might be causing those differences?

<details>
<summary>Answer</summary>

* This exercise is missing some results in `copy_mem`.
* The reason for the false-negatives stems from this exercise restricting the set of dynamic input accesses to those that flow from an entrypoint parameter source. The missing results mean that there are paths from entrypoint parameter sources to dynamic input access sinks that are missing edges between two data-flow nodes.
* Furthermore, this query does not exclude safe paths, if multiple paths exist, to a `DynamicInputAccess` that only has *some* paths that are unsafe.

</details>

### Optional: Exercise 10
This exercise does not improve the query's output but is a good example of the limitations of not using flow-state. To try to exclude safe interprocedural paths from the results, define function call arguments guarded by compliant type checks as barriers with the `isBarrier` predicate.

Think of this exercise as the opposite of the `isTypeNotValidated` predicate implemented in the previous exercises; we want to find a valid type validation guard and block flow through its basic block.

Implement the `isTypeValidationGuardCompliant` predicate and use it as part of the solution in `isBarrier` along with `typeValidationGuard`.

What is the problem with this implementation?

<details>
<summary>Answer</summary>

* This implementation will block flow through any basic block that contains a valid type validation guard for *any* `DynamicInputAccess` – not just the eventual sink. This means that if there are multiple paths to varying `DynamicInputAccess` sinks, the query will not output any results for that any sinks along that path even if the validation is mismatched.

</details>

## Exercise 11
Continuing from Exercise 9 (Exercise 10 is optional), there are still missing results. To identify the missing edges, we can debug our data-flow configuration. The CodeQL standard library provides the `Impl::FlowExploration` module, which exposes the `hasPartialFlow` predicate, allowing you to view partial flow paths. The `Impl::FlowExploration::PartialPathGraph` module must be imported to view the results of `hasPartialFlow` as paths.

This exercise only requires you to understand the query and evaluate its results; `Exercise10.ql` is otherwise complete. The query serves as a demonstration for using partial flow.

What is the missing edge?

<details>
<summary>Answer</summary>

* The missing edge is between the `input` parameter and return value of calls to `lock_input`.

</details>

## Exercise 12
In this final exercise for Part 2, in the global data-flow configuration, add an additional flow step between the `input` parameter and the result of calls to `lock_input` (represented as the `FunctionCall` itself) to add the missing edges.

<details>
<summary>Hint</summary>

* Use `Node::asExpr` to model the `input` parameter.

</details>

You should now see additional results through flow paths that include `lock_input`.

Optional: Re-add the barrier checks from `Exercise10` to see their impact on a larger set of results.

## Part 3: Flow-State
The second part of this workshop built upon the data-flow and control-flow analysis from the first part to further identify cases where type validation exists but does not match the subsequent access type. However, that rudimentary recursive control-flow analysis might not work in all cases, as it does not preserve flow path state in the case of multiple function calls with varying validation states.

To preserve the state of type validation checks across each data-flow path, we can use flow-state.

### Exercise 13
Definitions modelling the two possible states of type validation for a flow path to a `DynamicInputAccess`, validated and unvalidated, have been provided for you in this exercise. These states have been defined using `newtype` in order to create the [algebraic datatype](https://codeql.github.com/docs/ql-language-reference/types/#algebraic-datatypes) `TTypeValidationState`, which represents the possible states of type validation for a flow path to a `DynamicInputAccess`. Three classes have also been defined to extend from it using this [standard pattern](https://codeql.github.com/docs/ql-language-reference/types/#standard-pattern-for-using-algebraic-datatypes). Try to understand the syntax and the way these types have been structured before proceeding.

Secondly, the `InputToAccessConfig` data-flow configuration has been modified from the previous exercise to be stateful. Note the following four changes:
1. `InputToAccessConfig` now implements `DataFlow::StateConfigSig` rather than `DataFlow::ConfigSig`.
1. `InputToAccessConfig` now requires some changes to its predicate signatures to include state parameters.
1. `InputToAccessConfig` requires a declaration of a `FlowState` type, which in this example, is an alias to `TTypeValidationState`.
1. `InputToAccess` now constructs a data-flow computation using `DataFlow::MakeWithState<InputToAccessConfig>` rather than `DataFlow::Make<InputToAccessConfig>`.

It helps to approach implementing each predicate with an understanding of its purpose in stateful data-flow:
| Predicate                | Standard use-pattern                                     |
|--------------------------|----------------------------------------------------------|
| `isSource`               | Bind `state` to an initial state                         |
| `isSink`                 | Restrict sinks to those on paths with a specific `state` |
| `isAdditionalFlowStep/4` | Define state changes from `node1` to `node2`             |
| `isAdditionalFlowStep/2` | As before, define flow steps without a state change      |
| `isBarrier`              | Block flow through `node` with a specific `state`        |

Reimplement the new `isSource` and `isSink` predicates to bind state to `TypeUnvalidatedState`. Ignore the `isAdditionalFlowStep/4` and `isBarrier/2` predicates for now; they will be used in a later exercise. 

You should see the same results as in Exercise 12.

### Exercise 14
There are two primary ways to define state along a path:
1. Bind an initial state based on the source.
1. Change a state along a path based on a step between two nodes.

Those two approaches can also be used together.

In this workshop, we will use the second approach: changing state along a path. Start by defining those state-changing steps as part of the `TypeValidatedState` class. Modeling and exposing the state changing step as part of the flow state class is a common pattern used frequently in the CodeQL standard library.

Complete the characteristic predicate of `TypeValidatedState` to bind all of its field declarations, where:
* `node1` flows to `node2` in one step
* `node1` is not guarded by a validation check that `node2` is guarded by
* `call` is the call in the validation check `node2` is guarded by

Use `DataFlow::localFlowStep` to model the local flow step.

You should see 69 results.

### Exercise 15
Next, combine the class written in Exercise 14 with the stateful data-flow introduced in Exercise 13. Rather than recursively checking if a sink/access is type-validated, introduce that check along the flow path with `isAdditionalFlowStep/4`.

Reimplement the `isSink`, `isAdditionalFlowStep/4`, and `isBarrier` predicates.

**Important**: 
A peculiarity of flow-state is that modelling a state change in `isAdditionalFlowStep` for an edge that exists independently of this additional flow step created results in a duplicate subsequent flow path for *both* states. Therefore, `isBarrier` must be used to block that duplicate subsequent flow for the unwanted old state. Take the following example as a demonstration of this behavior. Assume that two states exist: `InitialState` and `ChangedState`. If `state_change(node)` is referenced in `isAdditionalFlowStep` but a matching reference in `isBarrier` for the `state_change` with `state instanceof InitialState` is missing, the flow state will be as follows:
```cpp
void flow_state_example(char* node) {
  *node; // state instanceof InitialState
  state_change(node); // arg_state instanceof InitialState, 
                      // return_state instanceof [InitialState, ChangedState]
  *node; // state instanceof [InitialState, ChangedState]
}
```

**Hint:**
Make sure to add a barrier to nodes on paths with a validated state but that are guarded by a type check with a type validation call not matching the call of the state (`state.(TypeValidatedState).getCall() != call_guarding_node`). 

You should now see 22 results.

### Exercise 16
Lastly, refine the output message of your query by accessing the state of the sink node. Use an `if/then/else` statement in the `where` clause of the query to check if the sink is validated or unvalidated and output a descriptive message for each case accordingly.

You can retrieve the state of a path node with `DataFlow::PathNode::getState()`. You can cast that state to the appropriate derived type if necessary.

You should see the same 22 results but with more descriptive messages.