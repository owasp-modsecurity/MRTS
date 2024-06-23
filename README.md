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

`baseid` defines the first `id` what a rule can use. Inside the generator increments that for every rule, and that variable is avaluable as `$CURRID` (see later).

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

`name` must be a unique name, and `template` is a text with the rule definition. This definition can contain macros - see [macros][#macros] section.

An example for `templates`:

```yaml
  - name: "SecRule for TARGETS"
    template: |
      SecRule $TARGET "$OPERATOR $OPARG" \
          "id:$CURRID,\
          phase:$PHASE,\
          deny,\
          t:none,\
          log,\
          msg:'%{MATCHED_VAR_NAME} was caught in phase:$PHASE',\
          ver:'$VERSION'"
```

As you can see the teplate macros begins with the dollar sign (`$`).

### macros

Marcos are coming from the definition. That can be from the unique definition or if there no such variable, then from the globals.

Avaliable macros:

* `$TARGET` the variable name when you want to check the SecRule's variable
* `$OPERATOR` is the used operator; it must be placed with the leading `@`, eg. `@rx`.
* `$OPARG` is the argument of the operator in the rule
* `$CURRID` is the incremented `id`, which guaranties that every generated rule will have a unique `id`
* `$PHASE` is the current phase in the list that you define in the definition file (see later its syntax)
* `$VERSION` is the `VERSION`, see above

Please note that `%{MATCHED_VAR_NAME}` is not a tool macro, but the ModSecurity's macro. You can use them where you want.

## Definition

In a definition file there also many keywords are avaliable. See an example then expand the meanings:

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
* `testdata` - list of expected test cases - see [testdata](#testdata) section

### testdata

`testdata` is a keyword in the definition file. Here you can list the necessary test case definitions. A testdata item can contain two member:

* `phase_methods` - where you can owerwrite the [default_tests_phase_methods](#default_tests_phase_methods) - this keyword is optional
* `targets` - here you can define the posible collection keys that can occurres in generated rules

#### test case defition

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

This will genreate a test case for collection key `/*` (usually used for `XML`), the data will be the given `XML` string, and the test add an extra header for `go-ftw` test.

## Run the tool

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
$ cd /util/generate_rules
$ ./generate-rules.py -r data/*.yaml -e ../../rules/ -t ../../tests/regression/tests/
```

If you finished the generation process, you can download `go-ftw` and run it.

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


$ ./go-ftw run --config .ftw.apache-mrts.yaml -d ../coreruleset/tests/regression/tests/
🛠️  Starting tests!
🚀 Running go-ftw!
👉 executing tests in file MRTS_002_ARGS.yaml
	running 100000-1: ✔ passed in 12.68614ms (RTT 54.816458ms)
	running 100000-2: ✔ passed in 10.743204ms (RTT 54.584567ms)
	running 100000-3: ✔ passed in 12.3017ms (RTT 55.248479ms)
	running 100000-4: ✔ passed in 11.771936ms (RTT 54.533389ms)
👉 executing tests in file MRTS_002_ARGS.yaml
	running 100001-1: ✔ passed in 9.864029ms (RTT 53.313677ms)
	running 100001-2: ✔ passed in 9.993946ms (RTT 53.594318ms)
	running 100001-3: ✔ passed in 9.412108ms (RTT 53.388277ms)
	running 100001-4: ✔ passed in 9.435627ms (RTT 53.400019ms)
...
```

## Check the state of covered variables

When you finished the build process, you can check which variables (and later the othe entities) are covered by the generated rule set.

You should type:

```bash
$ cd util/collect_rules

$ ./collect-rules.py 
usage: collect-rules.py [-h] -r [/path/to/mrts/*.conf ...]
collect-rules.py: error: the following arguments are required: -r/--rules
```

As you can see here are also a mandatory argument, the path of generated rules.

```bash
$ ./collect-rules.py -r ../../rules/*.conf
Config file: ../../rules/MRTS_001_INIT.conf
 Parsing ok.
Config file: ../../rules/MRTS_002_ARGS.conf
 Parsing ok.
Config file: ../../rules/MRTS_003_ARGS_COMBINED_SIZE.conf
 Parsing ok.
Config file: ../../rules/MRTS_110_XML.conf
 Parsing ok.

=====
Covered TARGETs: REQUEST_HEADERS, ARGS, ARGS_COMBINED_SIZE, XML

UNCOVERED TARGETs: ARGS_GET, ARGS_GET_NAMES, ARGS_NAMES, ...
```

Based on the output, we actually covered 4 targets, so there are lot of works to cover all variables.




