# MRTS

MRTS is a utility that helps you create rule sets and their tests for [ModSecurity](https://github.com/owasp-modsecurity/ModSecurity) or ModSecurity compliant engines (eg. [Coraza](https://github.com/corazawaf/coraza/)) for regression testing. The format of the test cases is compatible with [go-ftw](https://github.com/coreruleset/go-ftw/).

Please note that this project is in very beta state.

## Goals

The goals of this project:
* create as many rules as possible for ModSecurity to test its behavior
* create as many tests as possible for each rule

ModSecurity uses its rules [targets](https://github.com/owasp-modsecurity/ModSecurity/wiki/Reference-Manual-%28v2.x%29#user-content-Variables), [operators](https://github.com/owasp-modsecurity/ModSecurity/wiki/Reference-Manual-%28v2.x%29#user-content-Operators), [transformations](https://github.com/owasp-modsecurity/ModSecurity/wiki/Reference-Manual-%28v2.x%29#transformation-functions) (special actions) and so many other components. It is necessary to test their behavior.

Note, that [libmodsecurity3](https://github.com/owasp-modsecurity/ModSecurity/tree/v3/master) has a [regression test framework](https://github.com/owasp-modsecurity/ModSecurity/tree/v3/master/test) with several [test cases](https://github.com/owasp-modsecurity/ModSecurity/tree/v3/master/test/test-cases/regression), but it tests only the library, not the embedded state. For example we don't know anything about behavior of [Nginx connector](https://github.com/owasp-modsecurity/ModSecurity-nginx).

With the generated rules and tests we can check the operation of [mod-security2](https://github.com/owasp-modsecurity/ModSecurity/tree/v2/master) and [Nginx-connector](https://github.com/owasp-modsecurity/ModSecurity-nginx).

The generated rules can help in the quality assurance of these engines, e.g. after sending pull requests, we can verify that the change did not change the expected behavior.

## Idea

The idea is to generate rules to see what happens to a particular component. It's not as trivial as it seems at first glance. Consider there are 5 phases - can we be sure of behaviors are same in each phases? Variables can be collections, every combinations of collections works as we need? Do you want to check the variable against multiple operator? With multiple operator arguments?

It's easy to see that the number of possible combinations can be infinite. It could be too much efford to write a rule for every possible format - and a test case too.

Instead of doing this, we can make a description about the object, and expand the possible combinations and their test cases.

Rules are generated based on templates. You can define as many templates as you want, and you can apply them for each rule description.

The operation is very simple: create one or more configuration files, and run the generator script with those files. the format of the files is some structured data (YAML, JSON) which can be human readable (and writable). Generator will produce rules with combination of given:
* target + colkeys (collection keys) (eg. `ARGS:arg1`, `ARGS:arg2`, `ARGS:arg1|ARGS:arg2`)
* operators (you can pass multiple operators)
* operator arguments - also can pass several arguments
* phases - it depends on your choose, in which phases you want to check the target


## API

The framework has an API that describes which keywords can be used for the description. To avoid unwanted typing, there are several global settings that are derived in each case.

The syntax of API can be YAML or JSON.

### Global keywords

Every global settings should be put under the `global` keyword, eg:

```yaml
global:
  version: MRTS/0.1
  baseid: 100000
```

You can place `global` keywords in every file, each subsequent occurrence will overwrite the previous one. The files are processed in ABC order, later overwriting does not change the previous settings.

#### global

This keyword shows that the next block contains global settings.

#### version

`version` shows the current version of framework and can appear as constant in templates (see later).

#### baseid

`baseid` defines the first `id` what a rule can use. Inside the generator increments that for every rule, and that variable is avaluable as `${CURRID}$` (see later).

#### default_operator

This global variable defines the default operator for rules. You can overwrite it at every case, moreover you can add more operators for every case. But if you don't want to type, the `operator` member can be omitted.

Syntax:
```yaml
global:
  default_operator: "@rx"
```

#### templates

`templates` defines a list of templates. Each item in the list is a `template` block - see [template](#Template) section.

#### default_tests_phase_methods

This keyword describes an object. Each keys of the object is a phase value, and the value is the method what you prefer to send the request during the test (with `go-ftw`). In `phase:1` we prefer to use `GET` method, in case of each other the `POST`. Example:

```yaml
global:
  default_tests_phase_methods
  - 1: get
  - 2: post
  - 3: post
  - 4: post
  - 5: post
```

### Template

You can create one or more template which can be used for generated rules. A template object has two other named objects: `name` and `template`.

`name` must be a unique name, and `template` is a text with the rule definition. This definition can contain macros - see [macros](#macros) section.

An example for `templates`:

```yaml
  - name: "SecRule for TARGETS"
    template: |
      SecRule ${TARGET}$ "${OPERATOR}$ ${OPARG}$" \
          "id:${CURRID}$,\
          phase:${PHASE}$,\
          deny,\
          t:none,\
          log,\
          msg:'%{MATCHED_VAR_NAME} was caught in phase:${PHASE}$',\
          ver:'${VERSION}$'"
```

As you can see the template macros are delimited by `${...}$`.

### macros

Marcos are coming from the definition. That can be from the unique definition or if there no such variable, then from the globals.

Avaliable macros:

* `${TARGET}$` the variable name when you want to check the SecRule's variable
* `${OPERATOR}$` is the used operator; it must be placed with the leading `@`, eg. `@rx`.
* `${OPARG}$` is the argument of the operator in the rule
* `${CURRID}$` is the incremented `id`, which guaranties that every generated rule will have a unique `id`
* `${PHASE}$` is the current phase in the list that you define in the definition file (see later its syntax)
* `${VERSION}$` is the `VERSION`, see above
* `${ACTIONS}$` is the actions you want in the rule 
* `${DIRECTIVES}$` is the additional directives you want next to the rule 

Please note that `%{MATCHED_VAR_NAME}` is not a tool macro, but the ModSecurity's macro. You can use them where you want.

## Definition

In a definition file there also many keywords are available. See an example then expand the meanings:

```yaml
target: null
rulefile: MRTS_001_INIT.conf
testfile: null
objects:
- object: secaction
  actions:
    id: 10001
    phase: 1
    pass: null
    nolog: null
    msg: "'Initial settings'"
    ctl: ruleEngine=DetectionOnly
- object: secrule
  target: REQUEST_HEADERS:X-MRTS-Test
  operator: '@rx ^.*$'
  actions:
    id: 10002
    phase: 1
    pass: null
    t: none
    log: null
    msg: "'%{MATCHED_VAR}'"
```

or

```yaml
target: ARGS_COMBINED_SIZE
rulefile: MRTS_003_ARGS_COMBINED_SIZE.conf
testfile: MRTS_003_ARGS_COMBINED_SIZE.yaml
templates:
- SecRule for TARGETS
colkey:
- - ''
operator:
- '@lt'
oparg:
- 2
actions:
  - action:
      - status:404
directives:
  - directive: 
      - SecAction "id:${CURRID}$,phase:${PHASE}$, pass, setenv:'123=abc'"
testdata:
  phase_methods:
    1: get
    2: post
    3: post
    4: post
  targets:
    - target: 2
      test:
        data:
          foo: attack
    - target: arg1
      test:
        data:
          arg1: attack
    - target: arg2
      test:
        data:
          arg2: attack
```

* `target` - defines the variable name what you want to test; it can be null, but then you must define the expected rules or actions under the `object` block
* `rulefile` - the name of generated file; the path will be passed as cli argument, you should define here the relative path
* `testfile` - the name of generated test file; can be null if you don't want to make tests against rules. The path here also will be passed as cli argument.
* `objects` - a list type item, you can order the `object` which describes a `SecRule` or a `SecAction`. This is necessary because there are some special rules/actions, which can't described as regular rule. The first example generates the file `MRTS_001_INIT.conf` with a `SecAction` and a `SecRule`:

```
SecAction \
    "id:10001,\
    phase:1,\
    pass,\
    nolog,\
    msg:'Initial settings',\
    ctl:ruleEngine=DetectionOnly"

SecRule REQUEST_HEADERS:X-MRTS-Test "@rx ^.*$"\
    "id:10002,\
    phase:1,\
    pass,\
    t:none,\
    log,\
    msg:'%{MATCHED_VAR}'"
```

These are necessary for `go-ftw`.

* `templates` - you can list the name of templates what you want to apply
* `colkey` - list collection keys what you want to test; note that each item in the list is a list too! See this example:
```
colkey:
- - ''
- - arg1
- - arg1
  - arg2
- - /^arg_.*$/
```

will produce: `[[''], ['arg1'], ['arg2'], ['arg1', 'arg2'], ['/^arg_.*$']]`. This will generate rules with targets:

```
SecRule ARGS
SecRule ARGS:arg1
SecRule ARGS:arg1|ARGS:arg2
SecRule ARGS:/^arg_.*$/
```
* `operator` - list of used operators
* `oparg` - list of used operator arguments
* `actions` - list of used actions - see [actions](#actions) section 
* `directives` - list of used directives - see [directives](#directives) section
* `testdata` - list of expected test cases - see [testdata](#testdata) section

### actions

`actions` are defined for the `${ACTIONS}$` macro. See this example:

```yaml
actions:
  - action:
      - setvar:ABC=1
      - auditlog
      - status:400
  - action:
      - setvar:XYZ=2
      - status:500
```
Each `action` field contains a list of actions to be included in a SecRule/SecAction. Every `action` list will be used to generate different combinations of rules.

The above example used with this template:

```yaml
    template: |
      SecRule ${TARGET}$ "${OPERATOR}$ ${OPARG}$" \
          "id:${CURRID}$,\
          phase:${PHASE}$,\
          deny,\
          t:none,\
          log,\
          msg:'%{MATCHED_VAR_NAME} was caught in phase:${PHASE}$',\
          ver:'${VERSION}$',\
          ${ACTIONS}$"
```

would produce the following rules:

```yaml
SecRule ARGS "@contains attack" \
    "id:100000,\
    phase:2,\
    deny,\
    t:none,\
    log,\
    msg:'%{MATCHED_VAR_NAME} was caught in phase:2',\
    ver:'MRTS/0.1',\
    setvar:ABC=1,\
    auditlog,\
    status:400"

SecRule ARGS "@contains attack" \
    "id:100001,\
    phase:2,\
    deny,\
    t:none,\
    log,\
    msg:'%{MATCHED_VAR_NAME} was caught in phase:2',\
    ver:'MRTS/0.1',\
    setvar:XYZ=2,\
    status:500"
```

### directives

`directives` are defined for the `${DIRECTIVES}$` macro. See this example:
```yaml
directives:
  - directive:
      - SecAction "id:${CURRID}$,phase:${PHASE}$, pass, setenv:'123=abc'"
      - SecAction "id:${CURRID}$,phase:${PHASE}$, pass, setenv:'456=def'"
  - directive:
      - SecAction "id:${CURRID}$,phase:${PHASE}$, pass, setenv:'789=xyz'"
```
Each `directive` field contains a list of directives to be included in a template. Every `directive` list will be used to generate different combinations of rules. Macros are available and will be replaced with the current combination's value, except for macro `${CURRID}$` that is instead incremented at each substitution to guarantee a unique id per SecRule/SecAction.

The above example used with this template:

```yaml
    template: |
      SecRule ${TARGET}$ "${OPERATOR}$ ${OPARG}$" \
          "id:${CURRID}$,\
          phase:${PHASE}$,\
          deny,\
          t:none,\
          log,\
          msg:'%{MATCHED_VAR_NAME} was caught in phase:${PHASE}$',\
          ver:'${VERSION}$'"

      ${DIRECTIVES}$
```
would produce the following rules:
```yaml
SecRule ARGS "@contains attack" \
    "id:100000,\
    phase:2,\
    t:none,\
    log,\
    msg:'%{MATCHED_VAR_NAME} was caught in phase:2',\
    ver:'MRTS/0.1'"

SecAction "id:100001,phase:2, pass, setenv:'123=abc'"
SecAction "id:100002,phase:2, pass, setenv:'456=def'"

SecRule ARGS "@contains attack" \
    "id:100003,\
    phase:2,\
    t:none,\
    log,\
    msg:'%{MATCHED_VAR_NAME} was caught in phase:2',\
    ver:'MRTS/0.1'"

SecAction "id:100004,phase:2, pass, setenv:'789=xyz'"
```

### testdata

`testdata` is a keyword in the definition file. Here you can list the necessary test case definitions. A testdata item can contain two member:

* `phase_methods` - where you can overwrite the [default_tests_phase_methods](#default_tests_phase_methods) - this keyword is optional
* `targets` - here you can define the posible collection keys that can occurres in generated rules

#### test case definition

Let's see a test case definition example:

```yaml
  targets:
    - target: ''
      test:
        data:
          foo: attack
    - target: arg1
      test:
        data:
          arg1: attack
```

As it described above, `targets` is list of tests. A test case contains two keywords:
* `target` - describes the collection key which used at the rule (can be empty: ``)
* `test` - is an object

The `test` object can contains these keywords:
* `data` - which can be a single string or a key:value pair
* `input` - a structure which overrides the test case in predefined structure

Note, that the `go-ftw` test structure is hard-coded in the script, the `input` overwrites that structure.

The given example above contains two test cases: one if the collection key is empty, and another one if the collection key is the `arg1` - see the generated rules example above. You **must** give at least one test for each used collection keys at the rules definition!

Here are some examples for test cases:

```yaml
  targets:
    - target: ''
      test:
        data:
          foo: attack
    - target: ''
      test:
        data:
          arg1: attack
```

This will generate two test cases for empty collection key with data: `foo=attack` and `arg1=attack`.

```yaml
    - target: ''
      test:
        data:
          foo: attack
    - target: arg1
      test:
        data:
          arg1: attack
```

This will generate one test for empty collection key and one for the collection key `arg1`. The data for the first case will be `foo=attack` and `arg1=attack` for the second.

```yaml
  targets:
    - target: '/*'
      test:
        data:
          <level1><level2>foo</level2><level2>bar</level2></level1>
        input:
          headers:
            - name: Content-Type
              value: application/xml
```

This will generate a test case for collection key `/*` (usually used for `XML`), the data will be the given `XML` string, and the test add an extra header for `go-ftw` test.

#### Encoded request

The field `input.encoded_request` allows defining a whole request encoded in base64. When running the test, the request is decoded into bytes and sent verbatim as the input for this test case. This allows sending malformed requests. Using this field will override all other fields related to the request.
    
```yaml
    targets:
        - target: ''
          test:
            data: null
            input:
              encoded_request: R0VUIC8gSFRUUC8xLjENCkhvc3Q6IGxvY2FsaG9zdA0KDQo=
```

#### Uri

The field `input.uri` allows defining the uri used for the request manually. This is in particular useful for using the `/reflect` endpoint of [albedo](https://github.com/coreruleset/albedo) which allows defining what the server response should be from within the body of the post request that was sent.

```yaml
  targets:
    - target: ''
      test:
        data: '{"status": 201, "body": "<html>reflected-token</html>"}'
        input:
          headers:
            - name: Content-Type
              value: application/json
          uri: '/reflect'
        output:
          status: 201
          response_contains: "reflected-token"
```

### Constants
The yaml schema has a mechanism to handle global and local constants.

~~~yaml
global:
  default_constants:
    one: 1
    TWO: 2
    two_in_list:
      - 2
    FOO_IN_DICT:
      foo: attack
...

constants:
  HEADERS_IN_DICTIONARY:
    headers:
      - name: test
        value: test
      - name: one
        value: ~{one}~
      - name: 2
        value: ~{TWO}~
  template_in_list:
    - SecRule for TARGETS
    - Template with constants
  one: one
~~~

Global constants are defined under the `global.default_constants` field. They are accessible across files and are reset whenever a new `global` field is defined.

Local constants are defined under a `constants` field at the root of a file. They are only accessible in the file they are defined in.

#### Syntax
Constants are defined as key-value pairs where:

~~~yaml
NAME: VALUE
~~~

The name is used for referencing the constant and the value is used for the substitution. Referencing a constant can be done inside the value of any other key in the API. References use the `~{...}~` separators like so:

~~~yaml
~{NAME}~
~~~

Variable names can be lower or upper case and are case sensitive.

#### Properties

Constants can be yaml scalars, lists, or dictionaries:

~~~yaml
scalar: 1
list:
  - 1
dictionary:
  1: 1
~~~

Constants can reference other constants in their values:

~~~yaml
headers:
  - name: one
    value: ~{one}~
  - name: two
    value: ~{TWO}~
~~~

Local constants with the same name as global constants have precedence in their local scope:
~~~yaml
global:
  default_constants:
    ONE: 1
...
constants:
  ONE: one
...
key: ~{ONE}~  # substituted by 'one'
~~~
Values can contain multiple references, such as in templates:

~~~yaml
  - name: "Template with constants"
    template: |
      SecRule ~{target}~ "${OPERATOR}$ ${OPARG}$" \
          "id:${CURRID}$,\
          phase:${PHASE}$,\
          deny,\
          t:~{None}~,\
          log,\
          msg:'%{MATCHED_VAR_NAME} was caught in phase:${PHASE}$',\
          ver:'~{VERSION}~'"
~~~

### Output / additional checks

By default, the generator will produce checks for tests with `go-ftw`'s `expect_ids` field using the current rule id as parameter. If the associated rule matches and it's id put in the log, the test will pass.

To use additional check methods, the `output` field can be used to redefine this default behavior:
    
```yaml
    targets:
        - target:
          test:
            data:
              foo: attack
            output:
              status: 200
```

This will use the `status` check. The available checks are ([as of version 2.1.1 of the `go-ftw` yaml schema specs](https://github.com/coreruleset/ftw-tests-schema/blob/main/spec/v2.1.1/ftw.md)):
* `status` - the expected HTTP status code
* `response_contains` - a regex match on the response
* `[no_]log_contains` - a string match on the log
* `log.[no_]expect_ids` - a list of expected rule ids in the log
* `log.[no_]match_regex` - a regex match on the log
* `expect_error` - expect an error from the waf

For a full syntax of:
```yaml
          output:
            status: 200
            response_contains: HTTP/1.1
            log_contains: nothing
            no_log_contains: everything
            log:
                expect_ids:
                    - 123456
                no_expect_ids:
                    - 123456
                match_regex: id[:\s"]*123456
                no_match_regex: id[:\s"]*123456
            expect_error: true
```

To combine the default check on the current rule id with additional checks, the `expect_ids` field must be used in conjunction with the `output` field:
```yaml
          output:
            status: 200
            log:
                expect_ids: []
``` 

This way, the status check will be used in addition to the default rule id check.

For writing negative tests, you can also use the `no_expect_ids` test in the same way: 

```yaml
          output:
            log:
                no_expect_ids: []
``` 

This way, the current rule id will be appended and the check verifies it does not show up in logs.

Exact properties, syntax, available checks and parameters are dependent on the used version of `go-ftw`. The generator will simply replace what is defined under the `output` field in the corresponding field of the generated test case.

 As described for `go-ftw`,  [if any of the checks fail the test will fail](https://github.com/coreruleset/go-ftw?tab=readme-ov-file#how-log-parsing-works).

### Before(-each) and After(-each) rule generation additions

Content defined in test configuration files can be added around the default template generation.

~~~yaml
templates:
- SecRule for TARGETS

generation:
  before: |
    # STRING BEFORE ALL
    SecAction "id:${CURRID}$,phase:2, pass, setenv:'before=123'"
  after: |
    # STRING AFTER ALL
    SecAction "id:${CURRID}$,phase:2 pass, setenv:'after=789'"
  before_each: |
      # STRING BEFORE EACH
      SecAction "id:${CURRID}$,phase:${PHASE}$, pass, setenv:'before_each=456'"
  after_each: |
      # STRING AFTER EACH
      SecAction "id:${CURRID}$,phase:${PHASE}$, pass, setenv:'after_each=456'"
...
~~~

Under the `generation` section, four options exist to surround the generated configurations for the test:
- `before` Add the content at the beginning of the generated rule file, before any generation of the template.
- `after` Add the content at the end of the generated rule file, after any generation of the template.
- `before_each` Add the content before each generated rule using the template.
- `after_each` Add the content after each generated rule using the template.

Each section can use the `${CURRID}$` macro to guarantee a unique id to each SecRule/SecAction. `before_each` and `after_each` sections can use all other macros used in template generation.

The above example would generate the following rules:

```
# STRING BEFORE ALL
SecAction "id:100013,phase:2, pass, setenv:'before=123'"

# STRING BEFORE EACH
SecAction "id:100014,phase:2, pass, setenv:'before_each=456'"

SecRule ARGS:arg1 "@contains attack" \
    "id:100015,\
    phase:2,\
    deny,\
    t:none,\
    log,\
    msg:'%{MATCHED_VAR_NAME} was caught in phase:2',\
    ver:'MRTS/0.1'"

# STRING AFTER EACH
SecAction "id:100016,phase:2, pass, setenv:'after_each=456'"

# STRING BEFORE EACH
SecAction "id:100017,phase:2, pass, setenv:'before_each=456'"

SecRule ARGS:arg2 "@contains attack" \
    "id:100018,\
    phase:2,\
    deny,\
    t:none,\
    log,\
    msg:'%{MATCHED_VAR_NAME} was caught in phase:2',\
    ver:'MRTS/0.1'"

# STRING AFTER EACH
SecAction "id:100019,phase:2, pass, setenv:'after_each=456'"

# STRING AFTER ALL
SecAction "id:100020,phase:2 pass, setenv:'after=789'"
```

## Run the tool
### Run the entire toolchain

#### Required:
* [albedo](https://github.com/coreruleset/albedo)
* [go-ftw](https://github.com/coreruleset/go-ftw)
* apache2 with the modsecurity and proxy modules for using the `apache2_ubuntu` + ModSecurity V2 infrastructure

To run the tests on a provided configuration, run the tool:

~~~bash
$ ./mrts/mrts.py
usage: mrts.py [-h] -i /path/to/infra/ -r /path/to/mrts/*.yaml -e /path/to/mrts/rules/ -t /path/to/mrts/tests/ [-c]
               [-f /path/to/mrts/ftw.mrts.config.yaml] [-v]
mrts.py: error: the following arguments are required: -i/--infrastructure, -r/--rulesdef, -e/--expdir, -t/--testdir
~~~

As you can see there are few command line arguments.
* `-i` - WAF infrastructure files
* `-r` - rules definition files
* `-e` - export directory where rules will be written
* `-t` - export test directory where tests will be written
* `-c` - clean previously generated rule and test files
* `-f` - `go-ftw` custom configuration file, if you don't want to use the default file provided in the infrastructure directory
* `-v` - verbose output

For running without a custom `go-ftw` configuration, run the `mrts.py` script from the root directory of the project (or else provide a ftw configuration file with a correct relative path).

~~~bash
$ ./mrts/mrts.py -i config_infra/apache2_ubuntu/ -r config_tests/ -e generated/rules/ -t generated/tests/regression/tests/
Generate rules and tests
Launch backend
Launch infrastructure
Executing test set...
🎉🎉🎉 Success: test set passed
Backend shutdown
Infrastructure shutdown
MRTS completed
~~~

### Rule and test generation

To generate the rules and their tests, run the tool:

```bash
$ ./generate-rules.py 
usage: generate-rules.py [-h] -r [/path/to/mrts/*.yaml ...] -e /path/to/mrts/rules/ -t /path/to/mrts/tests/
generate-rules.py: error: the following arguments are required: -r/--rulesdef, -e/--expdir, -t/--testdir
```

As you can see there are few command line arguments.

* `-r` - rules' definition files
* `-e` - export directory where rules will be written
* `-t` - export test directory where tests will be written

```bash
$ ./mrts/generate-rules.py -r config_tests/*.yaml -e generated/rules/ -t generated/tests/regression/tests/
```

Once generated, rules need to be added to your ModSecurity configuration file.

Change `m̀rts.load` with your absolute path to the generated rules:
```
Include /Absolute/Path/To/MRTS/generated/rules/*.conf
```
In `modsecurity.conf` include your absolute path to `mrts.load`:

```
...

Include /Absolute/Path/To/MRTS/mrts.load
```
Don't forget to restart your server each time you generate new rules.

If you finished the generation and configuration process, you can download `go-ftw` and run it.

For more info about `go-ftw` please see its [README](https://github.com/coreruleset/go-ftw/) or CRS's [excellent documentation](https://coreruleset.org/docs/development/testing/).

Here is an example:

```bash
$ cat .ftw.apache-mrts.yaml 
---
logfile: '/var/log/apache2/error.log'
logmarkerheadername: 'X-MRTS-TEST'
logtype:
  name: 'apache'
  timeregex:  '\[([A-Z][a-z]{2} [A-z][a-z]{2} \d{1,2} \d{1,2}\:\d{1,2}\:\d{1,2}\.\d+? \d{4})\]'
  timeformat: 'ddd MMM DD HH:mm:ss.S YYYY'


$ ./go-ftw run --config .ftw.apache-mrts.yaml -d generated/tests/regression/tests/
🛠️ Starting tests!
🚀 Running go-ftw!
👉 executing tests in file MRTS_002_ARGS_A-GET.yaml
	running 100000-1: ✔ passed in 4.03606ms (RTT 51.456201ms)
	running 100000-2: ✔ passed in 2.100709ms (RTT 50.672271ms)
	running 100000-3: ✔ passed in 3.572981ms (RTT 51.673479ms)
	running 100000-4: ✔ passed in 2.85232ms (RTT 50.599715ms)
👉 executing tests in file MRTS_002_ARGS_A-GET.yaml
	running 100001-1: ✔ passed in 2.102875ms (RTT 50.515938ms)
	running 100001-2: ✔ passed in 2.188394ms (RTT 50.675838ms)
	running 100001-3: ✔ passed in 2.013156ms (RTT 50.583605ms)
	running 100001-4: ✔ passed in 1.750534ms (RTT 50.572695ms)
...
```

## Check the state of covered variables

When you finished the build process, you can check which variables (and later the other entities) are covered by the generated rule set.

You should type:

```bash
$ cd mrts/collect_rules

$ ./collect-rules.py 
usage: collect-rules.py [-h] -r [/path/to/mrts/*.conf ...]
collect-rules.py: error: the following arguments are required: -r/--rules
```

As you can see here are also a mandatory argument, the path of generated rules.

```bash
$ ./collect-rules.py -r ../../generated/rules/*.conf
Config file: ../../generated/rules/MRTS_001_INIT.conf
 Parsing ok.
Config file: ../../generated/rules/MRTS_002_ARGS.conf
 Parsing ok.
Config file: ../../generated/rules/MRTS_003_ARGS_COMBINED_SIZE.conf
 Parsing ok.
Config file: ../../generated/rules/MRTS_004_ARGS_GET.conf
 Parsing ok.
Config file: ../../generated/rules/MRTS_005_ARGS_GET_NAMES.conf
 Parsing ok.
Config file: ../../generated/rules/MRTS_110_XML.conf
 Parsing ok.

=====
Covered TARGETs: REQUEST_HEADERS, ARGS, ARGS_COMBINED_SIZE, ARGS_GET, ARGS_GET_NAMES, XML

UNCOVERED TARGETs: ARGS_NAMES, ARGS_POST, ARGS_POST_NAMES, ...
```

Based on the output, we actually covered 6 targets, so there are lot of works to cover all variables.




