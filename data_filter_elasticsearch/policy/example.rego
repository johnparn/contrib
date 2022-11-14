package example

import future.keywords.contains
import future.keywords.if
import future.keywords.in

### Entry point to the policy.
### Matches on incoming request.

default allow := false
# default claims := false
default jwt_groups_set := {}

# Rule matching collection of posts.
allow = true {
    # print("INPUT", input)
    # print("CLAIMS", input.token)
    input.method = "GET"
    input.path = ["posts"]
    allowed[x]
}

# Rule matching individual post.
allow = true {
    # print("INPUT", input)
    # print("CLAIMS", claims)
    input.method = "GET"
    input.path = ["posts", post_id]
    allowed[x]
    x.id = post_id
}

# See the 'JWT Decoding' example for an explanation.
claims := payload if {
	v := input.token #input.attributes.request.http.headers.authorization
	startswith(v, "Bearer ")
	t := substring(v, count("Bearer "), -1)
 	io.jwt.verify_hs256(t, "B41BD5F462719C6D6118E673A2389")
 	[_, payload, _] := io.jwt.decode(t)
}

# Working with string value "bob" in Authorization header
# allowed[x] {
#     x := data.elastic.posts[_]
#     v := input.token
#     startswith(v, "Bearer ")
# 	t := substring(v, count("Bearer "), -1)
#     print("Bearer", t)
#     x.author == t
# }

allowed[x] {
    print("CLAIMS2", claims.groups)
    x := data.elastic.posts[_]
    data_access_set = {y | y := claims.groups[_]}
    # print("INTERSECTION", data_access_set & jwt_groups_set)
    x.access == data_access_set & jwt_groups_set
}

jwt_groups_set := s {
    s := {y | y := claims.groups[_]}
}



# jwt_groups := jwt_groups_set if {
#     # Verify, unpack token
#     token := input.user;
#     print("USER: ", token)
#     bearer_token := substring(token, count("Bearer "), -1)
#     io.jwt.verify_hs256(bearer_token, "B41BD5F462719C6D6118E673A2389")
#     [_, payload, _] := io.jwt.decode(bearer_token)
#     print("PAYLOAD: ", payload)
#     jwt_groups_set := { j | j := payload.groups[_]}
# }

# jwt_payload := payload if {
# 	# Verify the signature on the Bearer token. In this example the secret is
# 	# hardcoded into the policy however it could also be loaded via data or
# 	# an environment variable. Environment variables can be accessed using
# 	# the `opa.runtime()` built-in function.
# 	io.jwt.verify_hs256(bearer_token, "B41BD5F462719C6D6118E673A2389")

# 	# This statement invokes the built-in function `io.jwt.decode` passing the
# 	# parsed bearer_token as a parameter. The `io.jwt.decode` function returns an
# 	# array:
# 	#
# 	#	[header, payload, signature]
# 	#
# 	# In Rego, you can pattern match values using the `=` and `:=` operators. This
# 	# example pattern matches on the result to obtain the JWT payload.
# 	[_, payload, _] := io.jwt.decode(bearer_token)
# }

# # Get bearer token
# bearer_token := t if {
# 	# Bearer tokens are contained inside of the HTTP Authorization header. This rule
# 	# parses the header and extracts the Bearer token value. If no Bearer token is
# 	# provided, the `bearer_token` value is undefined.
# 	v := input.attributes.request.http.headers.authorization
# 	startswith(v, "Bearer ")
# 	t := substring(v, count("Bearer "), -1)
# }


### Helper rules that implement data filtering & protection policy.

### Simple equality check.

# Return posts authored by input.user.

# OPA Query: "bob" = data.elastic.posts[_].author
# ES  Query: {name:author value:bob boost:<nil> queryName:TermQuery}
# Sample Output from Elasticsearch:
# {
#   "result": [
#     {
#       "id": "post1",
#       "author": "bob",
#       "message": "My first post",
#       "department": "dev",
#       "email": "bob@abc.com",
#       "clearance": 2,
#       "action": "read",
#       "resource": "",
#       "conditions": [],
#       "likes": [],
#       "followers": [],
#       "stats": []
#     },
#     {
#       "id": "post2",
#       "author": "bob",
#       "message": "My second post",
#       "department": "dev",
#       "email": "bob@abc.com",
#       "clearance": 2,
#       "action": "read",
#       "resource": "",
#       "conditions": [],
#       "likes": [],
#       "followers": [],
#       "stats": []
#     }
#   ]
# }
# allowed[x] {
#     x := data.elastic.posts[_]
#     # x.author == input.user
#     # es_groups_set := { y | y := x.access[_]}
#     # count(es_groups_set & jwt_groups_set) >= 1
#     es_groups_set := { y | y := x.access[_]}
#     es_groups_set & jwt_groups_set) >= 1
# }


# allowed[x] {
#     x := data.elastic.posts[_]
#     es_access_set := { y | y := x.access[_]}
#     print("ESGROUP", x.access)
#     print("JWTGROUP", jwt_groups_set)
#     count(es_access_set & jwt_groups_set) >= 1
#     # y := intersection[_]
#     # count(intersection) >= 1
# }

### Simple built-in functions like !=, >, <.

# Return posts with clearance level greater than 0 and less than equal to 5
# but no posts from "it".

# OPA Query: lte(data.elastic.posts[_].clearance, 5); gt(data.elastic.posts[_].clearance, 0); neq(data.elastic.posts[_].department, "it")
# ES  Query 1: {name:clearance from:<nil> to:5 timeZone: includeLower:true includeUpper:true boost:<nil> queryName: format: relation:}
# ES  Query 2: {name:clearance from:0 to:<nil> timeZone: includeLower:false includeUpper:true boost:<nil> queryName: format: relation:}
# ES  Query 3: {Query:<nil> mustClauses:[] mustNotClauses:[0xc0002ae240] filterClauses:[] shouldClauses:[] boost:<nil> minimumShouldMatch: adjustPureNegative:<nil> queryName:BoolMustNotQuery}
# Sample Output from Elasticsearch:
# {
#   "result": [
#     {
#       "id": "post1",
#       "author": "bob",
#       "message": "My first post",
#       "department": "dev",
#       "email": "bob@abc.com",
#       "clearance": 2,
#       "action": "read",
#       "resource": "",
#       "conditions": [],
#       "likes": [],
#       "followers": [],
#       "stats": []
#     },
#     {
#       "id": "post2",
#       "author": "bob",
#       "message": "My second post",
#       "department": "dev",
#       "email": "bob@abc.com",
#       "clearance": 2,
#       "action": "read",
#       "resource": "",
#       "conditions": [],
#       "likes": [],
#       "followers": [],
#       "stats": []
#     },
#     {
#       "id": "post4",
#       "author": "alice",
#       "message": "Hii world",
#       "department": "hr",
#       "email": "alice@xyz.com",
#       "clearance": 3,
#       "action": "read",
#       "resource": "",
#       "conditions": [],
#       "likes": [],
#       "followers": [],
#       "stats": []
#     },
#     {
#       "id": "post6",
#       "author": "ken",
#       "message": "Hii form Ken",
#       "department": "ceo",
#       "email": "ken@opa.com",
#       "clearance": 5,
#       "action": "read",
#       "resource": "",
#       "conditions": [],
#       "likes": [],
#       "followers": [],
#       "stats": []
#     }
#   ]
# }
# allowed[x] {
#     x := data.elastic.posts[_]
#     x.clearance <= 5
#     x.clearance > 0
#     x.department != "it"
# }

### Built-in functions like string contains and regexp.

# Return posts containing the term "OPA" in their message.

# OPA Query: contains(data.elastic.posts[_].message, "OPA")
# ES  Query: {queryString:*OPA* defaultField:message defaultOperator: analyzer: quoteAnalyzer: quoteFieldSuffix: allowLeadingWildcard:<nil> lowercaseExpandedTerms:<nil>
#             enablePositionIncrements:<nil> analyzeWildcard:<nil> locale: boost:<nil> fuzziness: fuzzyPrefixLength:<nil> fuzzyMaxExpansions:<nil> fuzzyRewrite: phraseSlop:<nil>
#             fields:[] fieldBoosts:map[] tieBreaker:<nil> rewrite: minimumShouldMatch: lenient:<nil> queryName:QueryStringQuery timeZone: maxDeterminizedStates:<nil> escape:<nil> typ:}
# Sample Output from Elasticsearch:
# {
#   "result": [
#     {
#       "id": "post7",
#       "author": "john",
#       "message": "OPA Good",
#       "department": "dev",
#       "email": "john@blah.com",
#       "clearance": 6,
#       "action": "read",
#       "resource": "",
#       "conditions": [],
#       "likes": [],
#       "followers": [],
#       "stats": []
#     },
#     {
#       "id": "post8",
#       "author": "ben",
#       "message": "This is OPA's time",
#       "department": "ceo",
#       "email": "ben@opa.com",
#       "clearance": 10,
#       "action": "read",
#       "resource": "",
#       "conditions": [],
#       "likes": [],
#       "followers": [],
#       "stats": []
#     }
#   ]
# }
# allowed[x] {
    # x := data.elastic.posts[_]
    # contains(x.message, "OPA")
# }

# Return posts who email address matches the ".org" domain.

# OPA Query: re_match("[a-zA-Z]+@[a-zA-Z]+.org", data.elastic.posts[_].email)
# ES  Query: {name:email regexp:[a-zA-Z]+@[a-zA-Z]+.org flags: boost:<nil> rewrite: queryName: maxDeterminizedStates:<nil>}
# Sample Output from Elasticsearch:
# {
#   "result": [
#     {
#       "id": "post9",
#       "author": "jane",
#       "message": "Hello from Jane",
#       "department": "it",
#       "email": "jane@opa.org",
#       "clearance": 7,
#       "action": "read",
#       "resource": "",
#       "conditions": [],
#       "likes": [],
#       "followers": [],
#       "stats": []
#     }
#   ]
# }
# allowed[x] {
#     x := data.elastic.posts[_]
#     re_match("[a-zA-Z]+@[a-zA-Z]+.org", x.email)
# }

### Nested examples which include a search.

# Return posts liked by input.user.

# OPA Query: "bob" = data.elastic.posts[_].likes[_].name
# ES  Query: {query:0xc00032a800 path:likes scoreMode: boost:<nil> queryName:NestedQuery innerHit:<nil> ignoreUnmapped:0xc0004985f8}
# Sample Output from Elasticsearch:
# {
#   "result": [
#     {
#       "id": "post10",
#       "author": "ross",
#       "message": "Hello from Ross",
#       "department": "it",
#       "email": "ross@opal.eu",
#       "clearance": 9,
#       "action": "read",
#       "resource": "",
#       "conditions": [],
#       "likes": [
#         {
#           "name": "bob"
#         }
#       ],
#       "followers": [],
#       "stats": []
#     }
#   ]
# }
# allowed[x] {
#     x := data.elastic.posts[_]
#     y := x.likes[_]
#     y.name = input.user
# }

# Return posts followed by input.user.

# OPA Query: "bob" = data.elastic.posts[_].followers[_].info.first
# ES  Query: {query:0xc0001f0b40 path:followers.info scoreMode: boost:<nil> queryName:NestedQuery innerHit:<nil> ignoreUnmapped:0xc00038a67c}
# Sample Output from Elasticsearch:
# {
#   "result": [
#     {
#       "id": "post11",
#       "author": "rach",
#       "message": "Hello from Rach",
#       "department": "it",
#       "email": "rach@opal.eu",
#       "clearance": 9,
#       "action": "read",
#       "resource": "",
#       "conditions": [],
#       "likes": [],
#       "followers": [
#         {
#           "info": {
#             "first": "bob",
#             "last": "doe"
#           }
#         }
#       ],
#       "stats": []
#     }
#   ]
# }
# allowed[x] {
#     x := data.elastic.posts[_]
#     y := x.followers[_]
#     y.info.first = input.user
# }

### Deeply nested example.

# Return posts by authors from CA.

# OPA Query: data.elastic.posts[_].stats[_].authorstat.authorbio.state = "CA"
# ES  Query: {query:0xc0004edd40 path:stats.authorstat.authorbio scoreMode: boost:<nil> queryName:NestedQuery innerHit:<nil> ignoreUnmapped:0xc0004f1471}
# Sample Output from Elasticsearch:
# {
#   "result": [
#     {
#       "id": "post12",
#       "author": "chan",
#       "message": "Hello from Chan",
#       "department": "it",
#       "email": "chan@opal.eu",
#       "clearance": 9,
#       "action": "read",
#       "resource": "cfgmgmt:nodes",
#       "conditions": [],
#       "likes": [],
#       "followers": [],
#       "stats": [
#         {
#           "authorstat": {
#             "authorbio": {
#               "country": "US",
#               "state": "CA",
#               "city": "San Fran"
#             }
#           }
#         }
#       ]
#     }
#   ]
# }
# allowed[x] {
#     x := data.elastic.posts[_]
#     y := x.stats[_]
#     y.authorstat.authorbio.state = "CA"
# }

# allowed[x] {
#     x := data.elastic.posts[_]
#     y := x.access
#     # groups_set := {v | v := y[_]}
#     groups_set := {x | x := claims.groups[_]}
#     # v := input.attributes.request.http.headers.authorization
#     allowed_groups := {"group2", "group3"}
#     has_access := groups_set & allowed_groups
#     count(has_access) >= 1
# }
