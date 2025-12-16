package mapper

import rego.v1

default claims := {}
default service := "unknown"

get_default(val, key, _) := val[key]
get_default(val, key, fallback) := fallback if not val[key]

method := lower(get_default(input.request.http, "method", "GET"))
dest := split(input.destination.principal, "/") # "spiffe://cluster.local/ns/default/sa/petstore"
service := dest[count(dest) - 1]
path := get_default(input.request.http, "path", "/")
auth := input.request.http.headers.authorization
token := split(auth, "Bearer ")[1]
claims := io.jwt.decode(token)[1]

porc := {
     "principal": claims,
     "operation": sprintf("%s:http:%s", [service, method]),
     "resource": {
        "id": sprintf("http://%s%s", [service, path]),
        "group": "mrn:iam:resource-group:allow-all"
      },
     "context": input,
}
