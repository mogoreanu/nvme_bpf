""" BPF build rules."""

def bpf_program(name, src, bpf_object, hdrs = [], clang_args="", **kwargs):
    native.genrule(
        name = name,
        srcs = [src] + hdrs + [
            "//:libbpf_headers",
            "//:libbpf_uapi_headers_files",
        ],
        outs = [bpf_object],
        cmd = """
            # Create a 'bpf' directory and copy libbpf headers there to satisfy <bpf/bpf_helpers.h>
            mkdir -p bpf
            for h in $(locations :libbpf_headers); do
                cp "$$h" bpf/
            done
            
            # Create 'linux' directory for uapi headers
            mkdir -p linux
            # Copy uapi headers. We filter for linux/ headers to avoid directory structure issues if glob returns more.
            # Assuming structure is include/uapi/linux/*.h in the source.
            # Flattening might be an issue if not careful, but here we just need 'linux/' prefix.
            for h in $(locations :libbpf_uapi_headers_files); do
                # Check if it is a linux header
                if [[ "$$h" == *"linux/"* ]]; then
                    cp "$$h" linux/
                fi
            done

            clang -g -O2 -target bpf \
                -D__TARGET_ARCH_x86 \
                %s \
                -I . \
                -I $$(pwd) \
                -I $(GENDIR) \
                -c $(location %s) \
                -o $@
        """ % (clang_args, src),
        **kwargs
    )

def bpf_skel(name, bpf_object, skel_header, **kwargs):
    native.genrule(
        name = name,
        srcs = [bpf_object],
        outs = [skel_header],
        tools = ["//:bpftool"],
        cmd = "$(location //:bpftool) gen skeleton $(location %s) > $@" % bpf_object,
        **kwargs
    )
