ARGS_NONE="pintos -v -k -T 60 -m 20   --fs-disk=10 -p tests/userprog/args-none:args-none --swap-disk=4 -- -q   -f run args-none"
ARGS_SINGLE="pintos -v -k -T 60 -m 20   --fs-disk=10 -p tests/userprog/args-single:args-single --swap-disk=4 -- -q   -f run 'args-single onearg'"
ARGS_MULTIPLE="pintos -v -k -T 60 -m 20   --fs-disk=10 -p tests/userprog/args-multiple:args-multiple --swap-disk=4 -- -q   -f run 'args-multiple some arguments for you!'"
ARGS_MANY="pintos -v -k -T 60 -m 20   --fs-disk=10 -p tests/userprog/args-many:args-many --swap-disk=4 -- -q   -f run 'args-many a b c d e f g h i j k l m n o p q r s t u v'"
ARGS_DBL_SPA="pintos -v -k -T 60 -m 20   --fs-disk=10 -p tests/userprog/args-dbl-space:args-dbl-space --swap-disk=4 -- -q   -f run 'args-dbl-space two  spaces!'"
HALT="pintos -v -k -T 60 -m 20   --fs-disk=10 -p tests/userprog/halt:halt --swap-disk=4 -- -q   -f run halt"
EXIT="pintos -v -k -T 60 -m 20   --fs-disk=10 -p tests/userprog/exit:exit --swap-disk=4 -- -q   -f run exit"
CREATE_NORMAL="pintos -v -k -T 60 -m 20   --fs-disk=10 -p tests/userprog/create-normal:create-normal --swap-disk=4 -- -q   -f run create-normal"
CREATE_MANY="pintos -v -k -T 60 -m 20   --fs-disk=10 -p tests/userprog/create-empty:create-empty --swap-disk=4 -- -q   -f run create-empty"
CREATE_NULL="pintos -v -k -T 60 -m 20   --fs-disk=10 -p tests/userprog/create-null:create-null --swap-disk=4 -- -q   -f run create-null"
CREATE_BAD_PTR="pintos -v -k -T 60 -m 20   --fs-disk=10 -p tests/userprog/create-bad-ptr:create-bad-ptr --swap-disk=4 -- -q   -f run create-bad-ptr"
CREATE_LONG="pintos -v -k -T 60 -m 20   --fs-disk=10 -p tests/userprog/create-long:create-long --swap-disk=4 -- -q   -f run create-long"
CREATE_EXIST="pintos -v -k -T 60 -m 20   --fs-disk=10 -p tests/userprog/create-exists:create-exists --swap-disk=4 -- -q   -f run create-exists"
CREATE_BOUND="pintos -v -k -T 60 -m 20   --fs-disk=10 -p tests/userprog/create-bound:create-bound --swap-disk=4 -- -q   -f run create-bound"
OPEN_NORMAL="pintos -v -k -T 60 -m 20   --fs-disk=10 -p tests/userprog/open-normal:open-normal -p ../../tests/userprog/sample.txt:sample.txt --swap-disk=4 -- -q   -f run open-normal"
OPEN_MISSING="pintos -v -k -T 60 -m 20   --fs-disk=10 -p tests/userprog/open-missing:open-missing --swap-disk=4 -- -q   -f run open-missing"
OPEN_BOUNDAR="pintos -v -k -T 60 -m 20   --fs-disk=10 -p tests/userprog/open-boundary:open-boundary -p ../../tests/userprog/sample.txt:sample.txt --swap-disk=4 -- -q   -f run open-boundary"
OPEN_EMPTY="pintos -v -k -T 60 -m 20   --fs-disk=10 -p tests/userprog/open-empty:open-empty --swap-disk=4 -- -q   -f run open-empty"
OPEN_NULL="pintos -v -k -T 60 -m 20   --fs-disk=10 -p tests/userprog/open-null:open-null --swap-disk=4 -- -q   -f run open-null"
OPEN_BAD_PTR="pintos -v -k -T 60 -m 20   --fs-disk=10 -p tests/userprog/open-bad-ptr:open-bad-ptr --swap-disk=4 -- -q   -f run open-bad-ptr"
OPEN_TWICE="pintos -v -k -T 60 -m 20   --fs-disk=10 -p tests/userprog/open-twice:open-twice -p ../../tests/userprog/sample.txt:sample.txt --swap-disk=4 -- -q   -f run open-twice"
CLOSE_NORMAL="pintos -v -k -T 60 -m 20   --fs-disk=10 -p tests/userprog/close-normal:close-normal -p ../../tests/userprog/sample.txt:sample.txt --swap-disk=4 -- -q   -f run close-normal"
CLOSE_TWICE="pintos -v -k -T 60 -m 20   --fs-disk=10 -p tests/userprog/close-twice:close-twice -p ../../tests/userprog/sample.txt:sample.txt --swap-disk=4 -- -q   -f run close-twice"
CLOSE_BAD_FD="pintos -v -k -T 60 -m 20   --fs-disk=10 -p tests/userprog/close-bad-fd:close-bad-fd --swap-disk=4 -- -q   -f run close-bad-fd"
READ_NORMAL="pintos -v -k -T 60 -m 20   --fs-disk=10 -p tests/userprog/read-normal:read-normal -p ../../tests/userprog/sample.txt:sample.txt --swap-disk=4 -- -q   -f run read-normal"
READ_BAD_PTR="pintos -v -k -T 60 -m 20   --fs-disk=10 -p tests/userprog/read-bad-ptr:read-bad-ptr -p ../../tests/userprog/sample.txt:sample.txt --swap-disk=4 -- -q   -f run read-bad-ptr"
READ_BOUNDAR="pintos -v -k -T 60 -m 20   --fs-disk=10 -p tests/userprog/read-boundary:read-boundary -p ../../tests/userprog/sample.txt:sample.txt --swap-disk=4 -- -q   -f run read-boundary"
READ_ZERO="pintos -v -k -T 60 -m 20   --fs-disk=10 -p tests/userprog/read-zero:read-zero -p ../../tests/userprog/sample.txt:sample.txt --swap-disk=4 -- -q   -f run read-zero"
READ_STDOUT="pintos -v -k -T 60 -m 20   --fs-disk=10 -p tests/userprog/read-stdout:read-stdout --swap-disk=4 -- -q   -f run read-stdout"
READ_BAD_FD="pintos -v -k -T 60 -m 20   --fs-disk=10 -p tests/userprog/read-bad-fd:read-bad-fd --swap-disk=4 -- -q   -f run read-bad-fd"
WRITE_NORMAL="pintos -v -k -T 60 -m 20   --fs-disk=10 -p tests/userprog/write-normal:write-normal -p ../../tests/userprog/sample.txt:sample.txt --swap-disk=4 -- -q   -f run write-normal"
WRITE_BAD_PT="pintos -v -k -T 60 -m 20   --fs-disk=10 -p tests/userprog/write-bad-ptr:write-bad-ptr -p ../../tests/userprog/sample.txt:sample.txt --swap-disk=4 -- -q   -f run write-bad-ptr"
WRITE_BOUNDARY="pintos -v -k -T 60 -m 20   --fs-disk=10 -p tests/userprog/write-boundary:write-boundary -p ../../tests/userprog/sample.txt:sample.txt --swap-disk=4 -- -q   -f run write-boundary"
WRITE_ZERO="pintos -v -k -T 60 -m 20   --fs-disk=10 -p tests/userprog/write-zero:write-zero -p ../../tests/userprog/sample.txt:sample.txt --swap-disk=4 -- -q   -f run write-zero"
WRITE_STDIN="pintos -v -k -T 60 -m 20   --fs-disk=10 -p tests/userprog/write-stdin:write-stdin --swap-disk=4 -- -q   -f run write-stdin"
WRITE_BAD_FD="pintos -v -k -T 60 -m 20   --fs-disk=10 -p tests/userprog/write-bad-fd:write-bad-fd --swap-disk=4 -- -q   -f run write-bad-fd"
FORK_ONCE="pintos -v -k -T 60 -m 20   --fs-disk=10 -p tests/userprog/fork-once:fork-once --swap-disk=4 -- -q   -f run fork-once"
FORK_MULTIPLE="pintos -v -k -T 60 -m 20   --fs-disk=10 -p tests/userprog/fork-multiple:fork-multiple --swap-disk=4 -- -q   -f run fork-multiple"
FORK_RECURSIVE="pintos -v -k -T 60 -m 20   --fs-disk=10 -p tests/userprog/fork-recursive:fork-recursive --swap-disk=4 -- -q   -f run fork-recursive"
FORK_READ="pintos -v -k -T 60 -m 20   --fs-disk=10 -p tests/userprog/fork-read:fork-read -p ../../tests/userprog/sample.txt:sample.txt --swap-disk=4 -- -q   -f run fork-read"
FORK_CLOSE="pintos -v -k -T 60 -m 20   --fs-disk=10 -p tests/userprog/fork-close:fork-close -p ../../tests/userprog/sample.txt:sample.txt --swap-disk=4 -- -q   -f run fork-close"
FORK_BOUNDARY="pintos -v -k -T 60 -m 20   --fs-disk=10 -p tests/userprog/fork-boundary:fork-boundary --swap-disk=4 -- -q   -f run fork-boundary"
EXEC_ONCE="pintos -v -k -T 60 -m 20   --fs-disk=10 -p tests/userprog/exec-once:exec-once -p tests/userprog/child-simple:child-simple --swap-disk=4 -- -q   -f run exec-once"
EXEC_ARG="pintos -v -k -T 60 -m 20   --fs-disk=10 -p tests/userprog/exec-arg:exec-arg -p tests/userprog/child-args:child-args --swap-disk=4 -- -q   -f run exec-arg"
EXEC_BOUNDAR="pintos -v -k -T 60 -m 20   --fs-disk=10 -p tests/userprog/exec-boundary:exec-boundary -p tests/userprog/child-simple:child-simple --swap-disk=4 -- -q   -f run exec-boundary"
EXEC_MISSING="pintos -v -k -T 60 -m 20   --fs-disk=10 -p tests/userprog/exec-missing:exec-missing --swap-disk=4 -- -q   -f run exec-missing"
EXEC_BAD_PTR="pintos -v -k -T 60 -m 20   --fs-disk=10 -p tests/userprog/exec-bad-ptr:exec-bad-ptr --swap-disk=4 -- -q   -f run exec-bad-ptr"
EXEC_READ="pintos -v -k -T 60 -m 20   --fs-disk=10 -p tests/userprog/exec-read:exec-read -p ../../tests/userprog/sample.txt:sample.txt -p tests/userprog/child-read:child-read --swap-disk=4 -- -q   -f run exec-read"
WAIT_SIMPLE="pintos -v -k -T 60 -m 20   --fs-disk=10 -p tests/userprog/wait-simple:wait-simple -p tests/userprog/child-simple:child-simple --swap-disk=4 -- -q   -f run wait-simple"
WAIT_TWICE="pintos -v -k -T 60 -m 20   --fs-disk=10 -p tests/userprog/wait-twice:wait-twice -p tests/userprog/child-simple:child-simple --swap-disk=4 -- -q   -f run wait-twice"
WAIT_KILLED="pintos -v -k -T 60 -m 20   --fs-disk=10 -p tests/userprog/wait-killed:wait-killed -p tests/userprog/child-bad:child-bad --swap-disk=4 -- -q   -f run wait-killed"
WAIT_BAD_PID="pintos -v -k -T 60 -m 20   --fs-disk=10 -p tests/userprog/wait-bad-pid:wait-bad-pid --swap-disk=4 -- -q   -f run wait-bad-pid"
MULTI_RECURSE="pintos -v -k -T 60 -m 20   --fs-disk=10 -p tests/userprog/multi-recurse:multi-recurse --swap-disk=4 -- -q   -f run 'multi-recurse 15'"
MULTI_CHILD_FD="pintos -v -k -T 60 -m 20   --fs-disk=10 -p tests/userprog/multi-child-fd:multi-child-fd -p ../../tests/userprog/sample.txt:sample.txt -p tests/userprog/child-close:child-close --swap-disk=4 -- -q   -f run multi-child-fd"
ROX_SIMPLE="pintos -v -k -T 60 -m 20   --fs-disk=10 -p tests/userprog/rox-simple:rox-simple --swap-disk=4 -- -q   -f run rox-simple"
ROX_CHILD="pintos -v -k -T 60 -m 20   --fs-disk=10 -p tests/userprog/rox-child:rox-child -p tests/userprog/child-rox:child-rox --swap-disk=4 -- -q   -f run rox-child"
ROX_MULTICHILD="pintos -v -k -T 60 -m 20   --fs-disk=10 -p tests/userprog/rox-multichild:rox-multichild -p tests/userprog/child-rox:child-rox --swap-disk=4 -- -q   -f run rox-multichild"
BAD_READ="pintos -v -k -T 60 -m 20   --fs-disk=10 -p tests/userprog/bad-read:bad-read --swap-disk=4 -- -q   -f run bad-read"
BAD_WRITE="pintos -v -k -T 60 -m 20   --fs-disk=10 -p tests/userprog/bad-write:bad-write --swap-disk=4 -- -q   -f run bad-write"
BAD_READ2="pintos -v -k -T 60 -m 20   --fs-disk=10 -p tests/userprog/bad-read2:bad-read2 --swap-disk=4 -- -q   -f run bad-read2"
BAD_WRITE2="pintos -v -k -T 60 -m 20   --fs-disk=10 -p tests/userprog/bad-write2:bad-write2 --swap-disk=4 -- -q   -f run bad-write2"
BAD_JUMP="pintos -v -k -T 60 -m 20   --fs-disk=10 -p tests/userprog/bad-jump:bad-jump --swap-disk=4 -- -q   -f run bad-jump"
BAD_JUMP2="pintos -v -k -T 60 -m 20   --fs-disk=10 -p tests/userprog/bad-jump2:bad-jump2 --swap-disk=4 -- -q   -f run bad-jump2"

# VM
PT_GROW_STACK="pintos -v -k -T 60 -m 20   --fs-disk=10 -p tests/vm/pt-grow-stack:pt-grow-stack --swap-disk=4 -- -q   -f run pt-grow-stack"
PT_GROW_BAD="pintos -v -k -T 60 -m 20   --fs-disk=10 -p tests/vm/pt-grow-bad:pt-grow-bad --swap-disk=4 -- -q   -f run pt-grow-bad"
PT_BIG_STK_OBJ="pintos -v -k -T 60 -m 20   --fs-disk=10 -p tests/vm/pt-big-stk-obj:pt-big-stk-obj --swap-disk=4 -- -q   -f run pt-big-stk-obj"
PT_BAD_ADDR="pintos -v -k -T 60 -m 20   --fs-disk=10 -p tests/vm/pt-bad-addr:pt-bad-addr --swap-disk=4 -- -q   -f run pt-bad-addr"
PT_BAD_READ="pintos -v -k -T 60 -m 20   --fs-disk=10 -p tests/vm/pt-bad-read:pt-bad-read -p ../../tests/vm/sample.txt:sample.txt --swap-disk=4 -- -q   -f run pt-bad-read"
PT_WRITE_CODE="pintos -v -k -T 60 -m 20   --fs-disk=10 -p tests/vm/pt-write-code:pt-write-code --swap-disk=4 -- -q   -f run pt-write-code"
PT_WRITE_CODE2="pintos -v -k -T 60 -m 20   --fs-disk=10 -p tests/vm/pt-write-code2:pt-write-code2 -p ../../tests/vm/sample.txt:sample.txt --swap-disk=4 -- -q   -f run pt-write-code2"
PT_GROW_STK="pintos -v -k -T 60 -m 20   --fs-disk=10 -p tests/vm/pt-grow-stk-sc:pt-grow-stk-sc --swap-disk=4 -- -q   -f run pt-grow-stk-sc"
PAGE_LINEAR="pintos -v -k -T 300 -m 20   --fs-disk=10 -p tests/vm/page-linear:page-linear --swap-disk=4 -- -q   -f run page-linear"
PAGE_PARALLEL="pintos -v -k -T 60 -m 20   --fs-disk=10 -p tests/vm/page-parallel:page-parallel -p tests/vm/child-linear:child-linear --swap-disk=4 -- -q   -f run page-parallel"
PAGE_MERGE_SEQ="pintos -v -k -T 600 -m 20   --fs-disk=10 -p tests/vm/page-merge-seq:page-merge-seq -p tests/vm/child-sort:child-sort --swap-disk=4 -- -q   -f run page-merge-seq"
PAGE_MERGE_PAR="pintos -v -k -T 600 -m 20   --fs-disk=10 -p tests/vm/page-merge-par:page-merge-par -p tests/vm/child-sort:child-sort --swap-disk=10 -- -q   -f run page-merge-par"
PAGE_MERGE_STK="pintos -v -k -T 60 -m 20   --fs-disk=10 -p tests/vm/page-merge-stk:page-merge-stk -p tests/vm/child-qsort:child-qsort --swap-disk=10 -- -q   -f run page-merge-stk"
PAGE_MERGE_MM="pintos -v -k -T 60 -m 20   --fs-disk=10 -p tests/vm/page-merge-mm:page-merge-mm -p tests/vm/child-qsort-mm:child-qsort-mm --swap-disk=10 -- -q   -f run page-merge-mm"
PAGE_SHUFFLE="pintos -v -k -T 600 -m 20   --fs-disk=10 -p tests/vm/page-shuffle:page-shuffle --swap-disk=4 -- -q   -f run page-shuffle"
MMAP_READ="pintos -v -k -T 60 -m 20   --fs-disk=10 -p tests/vm/mmap-read:mmap-read -p ../../tests/vm/sample.txt:sample.txt --swap-disk=4 -- -q   -f run mmap-read"
MMAP_CLOSE="pintos -v -k -T 60 -m 20   --fs-disk=10 -p tests/vm/mmap-close:mmap-close -p ../../tests/vm/sample.txt:sample.txt --swap-disk=4 -- -q   -f run mmap-close"
MMAP_UNMAP="pintos -v -k -T 60 -m 20   --fs-disk=10 -p tests/vm/mmap-unmap:mmap-unmap -p ../../tests/vm/sample.txt:sample.txt --swap-disk=4 -- -q   -f run mmap-unmap"
MMAP_OVERLAP="pintos -v -k -T 60 -m 20   --fs-disk=10 -p tests/vm/mmap-overlap:mmap-overlap -p tests/vm/zeros:zeros --swap-disk=4 -- -q   -f run mmap-overlap"
MMAP_TWICE="pintos -v -k -T 60 -m 20   --fs-disk=10 -p tests/vm/mmap-twice:mmap-twice -p ../../tests/vm/sample.txt:sample.txt --swap-disk=4 -- -q   -f run mmap-twice"
MMAP_WRITE="pintos -v -k -T 60 -m 20   --fs-disk=10 -p tests/vm/mmap-write:mmap-write --swap-disk=4 -- -q   -f run mmap-write"
MMAP_RO="pintos -v -k -T 60 -m 20   --fs-disk=10 -p tests/vm/mmap-ro:mmap-ro -p ../../tests/vm/large.txt:large.txt --swap-disk=4 -- -q   -f run mmap-ro"
MMAP_EXIT="pintos -v -k -T 60 -m 20   --fs-disk=10 -p tests/vm/mmap-exit:mmap-exit -p tests/vm/child-mm-wrt:child-mm-wrt --swap-disk=4 -- -q   -f run mmap-exit"
MMAP_SHUFFLE="pintos -v -k -T 600 -m 20   --fs-disk=10 -p tests/vm/mmap-shuffle:mmap-shuffle --swap-disk=4 -- -q   -f run mmap-shuffle"
MMAP_BAD_FD="pintos -v -k -T 60 -m 20   --fs-disk=10 -p tests/vm/mmap-bad-fd:mmap-bad-fd --swap-disk=4 -- -q   -f run mmap-bad-fd"
MMAP_CLEAN="pintos -v -k -T 60 -m 20   --fs-disk=10 -p tests/vm/mmap-clean:mmap-clean -p ../../tests/vm/sample.txt:sample.txt --swap-disk=4 -- -q   -f run mmap-clean"
MMAP_INHERIT="pintos -v -k -T 60 -m 20   --fs-disk=10 -p tests/vm/mmap-inherit:mmap-inherit -p ../../tests/vm/sample.txt:sample.txt -p tests/vm/child-inherit:child-inherit --swap-disk=4 -- -q   -f run mmap-inherit"
MMAP_MISALIGN="pintos -v -k -T 60 -m 20   --fs-disk=10 -p tests/vm/mmap-misalign:mmap-misalign -p ../../tests/vm/sample.txt:sample.txt --swap-disk=4 -- -q   -f run mmap-misalign"
MMAP_NULL="pintos -v -k -T 60 -m 20   --fs-disk=10 -p tests/vm/mmap-null:mmap-null -p ../../tests/vm/sample.txt:sample.txt --swap-disk=4 -- -q   -f run mmap-null"
MMAP_OVER_CODE="pintos -v -k -T 60 -m 20   --fs-disk=10 -p tests/vm/mmap-over-code:mmap-over-code -p ../../tests/vm/sample.txt:sample.txt --swap-disk=4 -- -q   -f run mmap-over-code"
MMAP_OVER_DATA="pintos -v -k -T 60 -m 20   --fs-disk=10 -p tests/vm/mmap-over-data:mmap-over-data -p ../../tests/vm/sample.txt:sample.txt --swap-disk=4 -- -q   -f run mmap-over-data"
MMAP_OVER_STK="pintos -v -k -T 60 -m 20   --fs-disk=10 -p tests/vm/mmap-over-stk:mmap-over-stk -p ../../tests/vm/sample.txt:sample.txt --swap-disk=4 -- -q   -f run mmap-over-stk"
MMAP_REMOVE="pintos -v -k -T 60 -m 20   --fs-disk=10 -p tests/vm/mmap-remove:mmap-remove -p ../../tests/vm/sample.txt:sample.txt --swap-disk=4 -- -q   -f run mmap-remove"
MMAP_ZERO="pintos -v -k -T 60 -m 20   --fs-disk=10 -p tests/vm/mmap-zero:mmap-zero --swap-disk=4 -- -q   -f run mmap-zero"
MMAP_BAD_FD2="pintos -v -k -T 60 -m 20   --fs-disk=10 -p tests/vm/mmap-bad-fd2:mmap-bad-fd2 --swap-disk=4 -- -q   -f run mmap-bad-fd2"
MMAP_BAD_FD3="pintos -v -k -T 60 -m 20   --fs-disk=10 -p tests/vm/mmap-bad-fd3:mmap-bad-fd3 --swap-disk=4 -- -q   -f run mmap-bad-fd3"
MMAP_ZERO_LEN="pintos -v -k -T 60 -m 20   --fs-disk=10 -p tests/vm/mmap-zero-len:mmap-zero-len --swap-disk=4 -- -q   -f run mmap-zero-len"
MMAP_OFF="pintos -v -k -T 60 -m 20   --fs-disk=10 -p tests/vm/mmap-off:mmap-off -p ../../tests/vm/large.txt:large.txt --swap-disk=4 -- -q   -f run mmap-off"
MMAP_BAD_OFF="pintos -v -k -T 60 -m 20   --fs-disk=10 -p tests/vm/mmap-bad-off:mmap-bad-off -p ../../tests/vm/large.txt:large.txt --swap-disk=4 -- -q   -f run mmap-bad-off"
MMAP_KERNEL="pintos -v -k -T 60 -m 20   --fs-disk=10 -p tests/vm/mmap-kernel:mmap-kernel -p ../../tests/vm/sample.txt:sample.txt --swap-disk=4 -- -q   -f run mmap-kernel"
LAZY_FILE="pintos -v -k -T 600 -m 20   --fs-disk=10 -p tests/vm/lazy-file:lazy-file -p ../../tests/vm/sample.txt:sample.txt -p ../../tests/vm/small.txt:small.txt --swap-disk=4 -- -q   -f run lazy-file"
LAZY_ANON="pintos -v -k -T 60 -m 20   --fs-disk=10 -p tests/vm/lazy-anon:lazy-anon --swap-disk=4 -- -q   -f run lazy-anon"
SWAP_FILE="pintos -v -k -T 180 -m 8   --fs-disk=10 -p tests/vm/swap-file:swap-file -p ../../tests/vm/large.txt:large.txt --swap-disk=10 -- -q   -f run swap-file"
SWAP_ANON="pintos -v -k -T 180 -m 10   --fs-disk=10 -p tests/vm/swap-anon:swap-anon --swap-disk=30 -- -q   -f run swap-anon"
SWAP_ITER="pintos -v -k -T 180 -m 10   --fs-disk=10 -p tests/vm/swap-iter:swap-iter -p ../../tests/vm/large.txt:large.txt --swap-disk=50 -- -q   -f run swap-iter"
SWAP_FORK="pintos -v -k -T 600 -m 40   --fs-disk=10 -p tests/vm/swap-fork:swap-fork -p tests/vm/child-swap:child-swap --swap-disk=200 -- -q   -f run swap-fork"
# VM

LG_CREATE="pintos -v -k -T 60 -m 20   --fs-disk=10 -p tests/filesys/base/lg-create:lg-create --swap-disk=4 -- -q   -f run lg-create"
LG_FULL="pintos -v -k -T 60 -m 20   --fs-disk=10 -p tests/filesys/base/lg-full:lg-full --swap-disk=4 -- -q   -f run lg-full"
LG_RANDOM="pintos -v -k -T 60 -m 20   --fs-disk=10 -p tests/filesys/base/lg-random:lg-random --swap-disk=4 -- -q   -f run lg-random"
LG_SEQ_BLOCK="pintos -v -k -T 60 -m 20   --fs-disk=10 -p tests/filesys/base/lg-seq-block:lg-seq-block --swap-disk=4 -- -q   -f run lg-seq-block"
LG_SEQ_RANDOM="pintos -v -k -T 60 -m 20   --fs-disk=10 -p tests/filesys/base/lg-seq-random:lg-seq-random --swap-disk=4 -- -q   -f run lg-seq-random"
SM_CREATE="pintos -v -k -T 60 -m 20   --fs-disk=10 -p tests/filesys/base/sm-create:sm-create --swap-disk=4 -- -q   -f run sm-create"
SM_FULL="pintos -v -k -T 60 -m 20   --fs-disk=10 -p tests/filesys/base/sm-full:sm-full --swap-disk=4 -- -q   -f run sm-full"
SM_RANDOM="pintos -v -k -T 60 -m 20   --fs-disk=10 -p tests/filesys/base/sm-random:sm-random --swap-disk=4 -- -q   -f run sm-random"
SM_SEQ_BLOCK="pintos -v -k -T 60 -m 20   --fs-disk=10 -p tests/filesys/base/sm-seq-block:sm-seq-block --swap-disk=4 -- -q   -f run sm-seq-block"
SM_SEQ_RANDOM="pintos -v -k -T 60 -m 20   --fs-disk=10 -p tests/filesys/base/sm-seq-random:sm-seq-random --swap-disk=4 -- -q   -f run sm-seq-random"
SYN_READ="pintos -v -k -T 300 -m 20   --fs-disk=10 -p tests/filesys/base/syn-read:syn-read -p tests/filesys/base/child-syn-read:child-syn-read --swap-disk=4 -- -q   -f run syn-read"
SYN_REMOVE="pintos -v -k -T 60 -m 20   --fs-disk=10 -p tests/filesys/base/syn-remove:syn-remove --swap-disk=4 -- -q   -f run syn-remove"
SYN_WRITE="pintos -v -k -T 60 -m 20   --fs-disk=10 -p tests/filesys/base/syn-write:syn-write -p tests/filesys/base/child-syn-wrt:child-syn-wrt --swap-disk=4 -- -q   -f run syn-write"
ALARM_SINGLE="pintos -v -k -T 60 -m 20   --fs-disk=10  --swap-disk=4 -- -q  -threads-tests -f run alarm-single"
ALARM_MULTIPLE="pintos -v -k -T 60 -m 20   --fs-disk=10  --swap-disk=4 -- -q  -threads-tests -f run alarm-multiple"
ALARM_SIMULTANEOUS="pintos -v -k -T 60 -m 20   --fs-disk=10  --swap-disk=4 -- -q  -threads-tests -f run alarm-simultaneous"
ALARM_PRIORITY="pintos -v -k -T 60 -m 20   --fs-disk=10  --swap-disk=4 -- -q  -threads-tests -f run alarm-priority"
ALARM_ZERO="pintos -v -k -T 60 -m 20   --fs-disk=10  --swap-disk=4 -- -q  -threads-tests -f run alarm-zero"
ALARM_NEGATIVE="pintos -v -k -T 60 -m 20   --fs-disk=10  --swap-disk=4 -- -q  -threads-tests -f run alarm-negative"
PRIORITY_CHANGE="pintos -v -k -T 60 -m 20   --fs-disk=10  --swap-disk=4 -- -q  -threads-tests -f run priority-change"
PRIORITY_DONATE_ONE="pintos -v -k -T 60 -m 20   --fs-disk=10  --swap-disk=4 -- -q  -threads-tests -f run priority-donate-one"
PRIORITY_DONATE_MULTI="pintos -v -k -T 60 -m 20   --fs-disk=10  --swap-disk=4 -- -q  -threads-tests -f run priority-donate-multiple"
PRIORITY_DONATE_MULTI="pintos -v -k -T 60 -m 20   --fs-disk=10  --swap-disk=4 -- -q  -threads-tests -f run priority-donate-multiple2"
PRIORITY_DONATE_NEST="pintos -v -k -T 60 -m 20   --fs-disk=10  --swap-disk=4 -- -q  -threads-tests -f run priority-donate-nest"
PRIORITY_DONATE_SEMA="pintos -v -k -T 60 -m 20   --fs-disk=10  --swap-disk=4 -- -q  -threads-tests -f run priority-donate-sema"
PRIORITY_DONATE_LOWER="pintos -v -k -T 60 -m 20   --fs-disk=10  --swap-disk=4 -- -q  -threads-tests -f run priority-donate-lower"
PRIORITY_FIFO="pintos -v -k -T 60 -m 20   --fs-disk=10  --swap-disk=4 -- -q  -threads-tests -f run priority-fifo"
PRIORITY_PREEMPT="pintos -v -k -T 60 -m 20   --fs-disk=10  --swap-disk=4 -- -q  -threads-tests -f run priority-preempt"
PRIORITY_SEMA="pintos -v -k -T 60 -m 20   --fs-disk=10  --swap-disk=4 -- -q  -threads-tests -f run priority-sema"
PRIORITY_CONDVAR="pintos -v -k -T 60 -m 20   --fs-disk=10  --swap-disk=4 -- -q  -threads-tests -f run priority-condvar"
PRIORITY_DONATE_CHAIN="pintos -v -k -T 60 -m 20   --fs-disk=10  --swap-disk=4 -- -q  -threads-tests -f run priority-donate-chain"
COW_SIMPLE="pintos -v -k -T 60 -m 20   --fs-disk=10 -p tests/vm/cow/cow-simple:cow-simple --swap-disk=4 -- -q   -f run cow-simple"


cd vm
make clean
make -j
cd build
source ../../activate

# $PT_GROW_BAD
$PT_BIG_STK_OBJ
# pintos -v -k  -m 20  --fs-disk=10 -p tests/userprog/args-multiple:args-multiple --swap-disk=4 -- -q   -f run 'args-multiple some arguments for you!'