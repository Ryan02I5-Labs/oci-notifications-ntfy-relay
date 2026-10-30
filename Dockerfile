# Official Fn Project Python images, pinned by multi-arch index digest
# (linux/amd64 and linux/arm64). Dependabot updates the digests.
FROM fnproject/python:3.12-dev@sha256:e956fadcbd7703d9fb8092e1964de0f44fe93f132a8c294414bde5ffc417699e AS build-stage

WORKDIR /function
COPY requirements.txt /function/
RUN python3.12 -m pip install --no-cache-dir --index-url https://pypi.org/simple --target /python/ -r requirements.txt && \
    test -x /python/bin/fdk

COPY func.py /function/

FROM fnproject/python:3.12@sha256:a51e9a800571837471de03253d4100f05d8dbd6f5a6a22e2118854cbe75b1163

WORKDIR /function
COPY --from=build-stage /python /python
COPY --from=build-stage /function /function
ENV PYTHONPATH=/function:/python
ENTRYPOINT ["/python/bin/fdk", "/function/func.py", "handler"]
