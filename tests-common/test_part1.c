typedef unsigned long size_t;
void *memcpy(void *dest, const void *src, size_t n);
int printf(const char *format, ...);

#define DYN_INPUT_TYPE_NONE 0x0
#define DYN_INPUT_TYPE_MEM 0x1
#define DYN_INPUT_TYPE_VAL 0x2

typedef union dyn_input {
  int val;
  struct {
    void *buf;
    size_t size;
  } ptr;
} dyn_input_t;

/**
 * A helper function which returns a packed unsigned integer value representing
 * a dynamic input type, where `p0` is the type of the first input and `p1` is
 * the type of the second input.
 */
unsigned int DYN_INPUT_TYPE(unsigned int p0, unsigned int p1) {
  return ((p0) | ((p1) << 4));
}

/**
 * Functions called from entrypoints that receive and process dynamic inputs.
 */
void copy_mem_nested(dyn_input_t *input) {
  memcpy(input[0].ptr.buf, input[1].ptr.buf,
         input[1].ptr.size); // path-dependent
}

int copy_mem(unsigned int unused, dyn_input_t *input,
             unsigned int input_types) {
  memcpy(input[0].ptr.buf, input[1].ptr.buf,
         input[1].ptr.size); // NON_COMPLIANT - type not checked
  copy_mem_nested(input);    // NON_COMPLIANT - type not checked

  if (input_types != DYN_INPUT_TYPE(DYN_INPUT_TYPE_MEM, DYN_INPUT_TYPE_MEM)) {
  }

  memcpy(input[0].ptr.buf, input[1].ptr.buf,
         input[1].ptr.size); // NON_COMPLIANT - guard doesn't control all paths
  copy_mem_nested(input);    // NON_COMPLIANT - guard doesn't control all paths

  if (DYN_INPUT_TYPE(DYN_INPUT_TYPE_MEM, DYN_INPUT_TYPE_MEM) == 100) {
    memcpy(input[0].ptr.buf, input[1].ptr.buf,
           input[1].ptr.size); // NON_COMPLIANT - useless type check
  }

  if (input_types != DYN_INPUT_TYPE(DYN_INPUT_TYPE_MEM, DYN_INPUT_TYPE_MEM)) {
    return 1;
  }

  memcpy(input[0].ptr.buf, input[1].ptr.buf,
         input[1].ptr.size); // COMPLIANT - type checked
  copy_mem_nested(input);    // COMPLIANT - type checked

  return 0;
}

int print_val(dyn_input_t *input, unsigned int input_types) {
  if (input_types == DYN_INPUT_TYPE(DYN_INPUT_TYPE_VAL, DYN_INPUT_TYPE_NONE)) {
    printf("%d", input[0].val++); // COMPLIANT - type checked
    printf("%d", input[0].val++); // COMPLIANT - type checked
    return 0;
  }

  printf("%d", input[0].val++); // NON_COMPLIANT - type not checked
  printf("%d", input[0].val++); // NON_COMPLIANT - type not checked
  return 1;
}

int write_val_to_mem(dyn_input_t *input, unsigned int input_types) {
  if (input_types == DYN_INPUT_TYPE(DYN_INPUT_TYPE_VAL, DYN_INPUT_TYPE_MEM)) {
    memcpy(input[1].ptr.buf, &input[0].val,
           sizeof(input[0].val)); // COMPLIANT - type checked
    return 0;
  }

  memcpy(input[1].ptr.buf, &input[0].val,
         sizeof(input[0].val)); // NON_COMPLIANT - type not checked
  return 1;
}

/**
 * Entrypoints that have the following parameters:
 * 1. An array, `input`, of two dyn_input_t dynamic inputs
 * 2. An unsigned int, `input_types`, describing the type of each input to be
 * compared against `DYN_INPUT_TYPE`.
 */
int EP_copy_mem(dyn_input_t input[2], unsigned int input_types) {
  return copy_mem(0, input, input_types);
}

int EP_print_val(dyn_input_t input[2], unsigned int input_types) {
  return print_val(input, input_types);
}

int EP_write_val_to_mem(dyn_input_t input[2], unsigned int input_types) {
  return write_val_to_mem(input, input_types);
}