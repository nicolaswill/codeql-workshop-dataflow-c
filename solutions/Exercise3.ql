import cpp

from Function f
where f.hasName(["EP_copy_mem", "EP_print_val", "EP_write_val_to_mem"])
select f, f.getParameter(0), f.getParameter(1)
