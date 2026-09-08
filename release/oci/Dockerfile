# Runtime index and platform manifests are retained in base-image.json.
FROM debian:bookworm-slim@sha256:88200866dfff7ea7f5cbcb6ec7c8a701889efe6fe859fe64d6990e4b07ea4171

# No compiler, downloaded installer, secret or fixture configuration is included.
COPY package /opt/kasumi
COPY binary-sha256 /opt/kasumi/binary-sha256
RUN cd /opt/kasumi && sha256sum --check binary-sha256 \
    && case "$(dpkg --print-architecture)" in arm64) elf_machine=183;; amd64) elf_machine=62;; *) exit 1;; esac \
    && for binary in bin/kasumid bin/kasumictl bin/kasumi-authority; do \
         test "$(od -An -tx1 -N6 "$binary" | tr -d ' \n')" = 7f454c460201 \
         && test "$(od -An -tu2 -j18 -N2 "$binary" | tr -d ' \n')" = "$elf_machine" || exit 1; \
       done \
    && groupadd --gid 65532 kasumi \
    && useradd --uid 65532 --gid 65532 --no-create-home --home-dir /var/lib/kasumi \
       --shell /usr/sbin/nologin kasumi \
    && install -d -m 0700 -o 65532 -g 65532 /var/lib/kasumi
USER 65532:65532
WORKDIR /var/lib/kasumi
STOPSIGNAL SIGTERM
ENTRYPOINT ["/opt/kasumi/bin/kasumid"]
CMD ["serve", "/var/lib/kasumi/installation/kasumi.json"]
