# The fuzzing build image, pinned by digest like every other base
# image here. ClusterFuzzLite builds the harnesses under fuzz/ against
# the same hash-pinned tree the application runs, so a crash it finds
# is a crash in the shipped parsers, not in a lookalike.
FROM gcr.io/oss-fuzz-base/base-builder-python@sha256:6b2b3a7e4a2da50de47f94925cffbe34747e1aae4f33d7f07ba6c681dd648b23
COPY . $SRC/manifest-identity
WORKDIR $SRC/manifest-identity
COPY .clusterfuzzlite/build.sh $SRC/
