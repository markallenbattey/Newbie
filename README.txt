Newbie 1.0 User Guide

Welcome to Newbie! A simple command-line tool for file processing, text manipulation, and automation.

Newbie is a rapid text processor, designed to not explode in memory even when processing very large files. It is also scripting language designed to be easy to learn and use. Every command starts with `&`, and you can chain them together to do powerful things with your files. The reason all the keywords begin with & is because Newbie has no string delimiters or escape characters. In order to achieve this, Newbie has to parse differently, out to the next &keyword instead of to the next whitespace or quotation mark. This difference makes it exceptionally powerful for text pre-processing. You can do rapid complex bulk text modification, without using regex, sed or grep. If you don't know what I'm talking about, don't worry about it. You won't have to know these things in order to use Newbie. If you do know what I'm talking about, you will appreciate not having any string delimiters or escape characters. When those old Unix tools were first developed, they used them to modify their code, as well as their data. Almost no one edits code that way, anymore, therefore newbie does not require escape characters.

In Newbie you explicitly state what gets displayed on the screen with the &show command. This command is always leftmost, and so may be deleted to enable silent execution in scripts. When the &show command is used the user is assumed to be human, and the output is paginated, etc.

Newbie features a readable pattern language, which is documented in the section on the &find command. This is a very critical feature, and I considered moving it up in the documentation, but it makes sense where it is.

Newbie runs at a slightly lower priority than the user interface components, which does somewhat slow it, but it enables the critical feature of being able to lock your desktop and walk away while processing large files. Otherwise, Newbie would hog the disk and your system would crash when you attempt to unlock the desktop. 

GETTING STARTED

To start in interactive mode (type commands one at a time):
	newbie

Run a script (execute a .ns file):
	newbie myscript.ns

Display this user guide:
	&guide

Exit Newbie:
	&exit

Display the license:
	&license

BASIC FILE OPERATIONS

Show a file:
	&show myfile.txt

Show just the first 10 lines. Note that Newbie generally deals with lines rather than characters. This is part of how it works without string delimiters. The end of a line and &keyword are significant boundaries to the Newbie parser. By default, Newbie truncates long lines at the width of your terminal. The &wrap command toggles this behavior.

	&show myfile.txt &first 10

Show the last 5 lines:
	&show myfile.txt &last 5

List files in current directory:
	&show &files

List files in a directory:
	&show &files ~/Documents/

List files matching a wildcard pattern:
	&show &files *.txt

Copy a file (&copy is really just a passthrough to the rsync -a command):
	&copy source.txt &to destination.txt

Move or rename a file:
	&move oldname.txt &to newname.txt

Delete a file or directory:
	&delete unwanted.txt
	&delete old_directory/

Convert file formats. After testing I found the standalone Linux components much faster than the rust crates, and so Newbie uses these, as opposed to native rust. Note that the following file compression formats are transparent in Newbie:
	&convert myfile.txt &into myfile.bz2
	&convert myfile.bz2 &into myfile.gz
	&convert myfile.gz &into myfile.xz
	&convert myfile.xz &into myfile.zst
	&convert myfile.zst &into copiedmyfile.txt

WRITING TO FILES

Write to a file. Note that &write always appends:
	&write Hello, World! &to greeting.txt
	&write Another line &to greeting.txt

RUNNING EXTERNAL COMMANDS

Run a bash command:
	&run &bash ls

Run a BASH command and see the output. Note that this will not work with other full screen cli programs like vim or nano. Use another BASH session or a GUI editor:
	&show &run &bash date
	
Do not attempt to run full screen cli apps within Newbie, such as nano or vim. Use another instance of bash for these. Personally, I use a GUI editor.

Run a Newbie script from within a script or interactive session:
	&run myscript.ns

Run a Bash script from within a script or interactive session:
	&run &bash script.sh

VARIABLES

Variables always start with `&v.` and you can use them to store and reuse values:
	&v.name &= Tux Penguin
	&v.age &= 30
	&write Hello, &v.name! You are &v.age years old. &to output.txt

See the value of a variable:
	&show &v.name

See the value of all variables:
	&vars

Clear one variable:
	&v.number &= 1
	&show &v.number
	&empty &v.number
	&show &v.number

Clear multiple variables at once:
	&empty &v.name &v.age 

SYSTEM VARIABLES

Newbie provides some built-in variables, most of these are just the BASH environment variables, along with things that are native to Rust:
	&show &system.user
	&show &system.hostname
	&show &system.path
	&show &system.home
	&show &system.shell
	&show &system.pwd
	&show &system.os
	&show &system.arch
	&show &system.timestamp
	&show &system.time
	&show &system.date
	&show &system.temp
	&write Report generated by &system.user on &system.date &to report.txt

PROCESS VARIABLES

Information about the currently running Newbie process:
	&show &process.pid
	&show &process.ppid
	&show &process.args
	&show &process.argc
	&show &process.cwd

NETWORK VARIABLES

Basic network connectivity information:
	&show &network.connected
	&show &network.local_ip

CONDITIONAL EXECUTION

In Newbie a user variable can have two states: in use, or not.
	&v.name &= Tux Penguin
	&if &v.name &write Name is set: &v.name &to log.txt

Check if a file exists:
	&if myfile.txt &write File exists! &to status.txt

Empty variables don't execute in this case:
	&empty &v.name
	&if &v.name &write This won't execute &to log.txt

To execute when variable is empty:
	&not &if &v.name &write Variable is empty &to log.txt

To execute when file doesn't exist:
	&not &if missing.txt &write File not found &to errors.txt

Check two conditions:
	&v.id &= 7
	&v.name &= Tux Penguin
	&if &v.id &if &v.name &write &v.id: &v.name &to valid.txt

Check one, negate another:
	&if &v.id &not &if &v.label &write ID &v.id has no label &to errors.txt

THE &find COMMAND - PATTERN MATCHING

The `&find` command is Newbie's powerful pattern matching tool for searching text in files. Unlike traditional tools like `grep`, `&find` uses an intuitive pattern language that combines literal text, character classes, variables, and positional operators.

Syntax:
	[&show] &find <pattern> &in <file> [&into filename] [options]

IMPORTANT: &find runs silently by default. To see results, use &show:
	&show &find error &in logfile.txt

Or write to a file:
	&find error &in logfile.txt &into matches.txt

Note: Both input and output files can be compressed in any of the formats supported by &convert.

Required components:
	<pattern> - The search pattern (see Pattern Syntax below)
	&in <file> - The file to search (supports compressed files)

Optional components:
	&into filename - Write results to a file instead of displaying
	&first N - Return only the first N matches
	&last N - Return only the last N matches (buffered)
	&numbered - Show line numbers (1, 2, 3...)
	&lines - Show original line numbers from source file

PATTERN SYNTAX

Literal Text - Match exact text by typing it directly:
	&find error &in logfile.txt
	&find Connection refused &in server.log

Character Classes - Match specific types of characters with variable-length or fixed-length patterns.

Variable-length (one or more):
	&numbers      Matches one or more digits
	&letters      Matches one or more letters (a-z, A-Z)
	&spaces       Matches one or more spaces
	&tabs         Matches one or more tabs

Fixed-length:
	&numbers 4    Matches exactly 4 digits
	&letters 3    Matches exactly 3 letters
	&spaces 2     Matches exactly 2 spaces
	&tabs 1       Matches exactly 1 tab

Examples:

Find lines with IP addresses (digits separated by dots):
	&find &numbers . &numbers . &numbers . &numbers &in access.log

Find 5-digit ZIP codes:
	&find &numbers 5 &in addresses.txt

Find lines with 3-letter abbreviations:
	&find &letters 3 &in data.txt

THE &+ (ADJACENCY) OPERATOR

By default, pattern components can have any amount of text between them. The `&+` operator requires components to be immediately adjacent with no space between.

Without &+: matches "error   123" or "error123" or "error abc 123":
	&find error &numbers &in file.txt

With &+: matches only "error123" (no space allowed):
	&find error &+ &numbers &in file.txt

Multiple adjacency: match "ID-12345":
	&find ID &+ - &+ &numbers 5 &in records.txt

START AND END ANCHORS

&start and &end control whether patterns must match at the beginning or end of lines.

Matches only lines that begin with ERROR:
	&find &start &= ERROR &in logfile.txt

Matches only lines that end with .txt:
	&find &end &= .txt &in filelist.txt

Matches lines that both start with ERROR and end with timeout:
	&find &start &= ERROR &end &= timeout &in logfile.txt

USING VARIABLES IN PATTERNS

You can use variables in patterns to make them dynamic:
	&v.status &= ERROR
	&find &v.status &in logfile.txt

THE &capture COMMAND - EXTRACTING DATA

While &find just searches for patterns, &capture extracts specific parts of matching lines into variables. The syntax is identical to &find but with variable names in the pattern. &capture is almost always used in a block, though it does support use at the interface.

Syntax:
	[&show] &capture <pattern_with_vars> &in <file> [&into <o>] [options]

Extract simple values with literals as fences:
	&capture ID: &v.id Name: &v.name &in records.txt

After this command, &v.id and &v.name contain the extracted values.

Write captured data to a file:
	&capture Error &v.code at &v.time &in log.txt &write &v.code,&v.time &to errors.csv

Use start anchor to match beginning of line:
	&capture &start &= [&v.date] &v.level : &v.msg &in system.log &write &v.date|&v.level|&v.msg &to structured.txt

Capture with character classes:
	&capture User &v.name logged in at &v.time &in auth.log

WORKING WITH BLOCKS

The &block command processes a file line-by-line, executing commands for each line. Each line is available in &newbie.line.

Basic syntax:
	&block datafile.txt
		(commands to execute for each line)
	&endblock

Example: Extract status for each line:
	&block data.txt
		&v.line &= &newbie.line
		&capture STATUS: &v.status ID: &v.id &in &v.line
		&if &v.status &write &v.id : &v.status &to status_report.txt
	&endblock

SORTING AND LOOKUP

Sort a file (preserves compression format):
	&sort input.txt &into sorted.txt
	&sort data.bz2 &into sorted_data.bz2

Sort with custom temporary directory:
	&sort huge_file.txt &temp /mnt/large_drive &into sorted.txt

Sort a huge file, using large external drive:
	&sort /run/media/mark/bigdrive/Archive/latest-truthy.nt.bz2 &temp /run/media/mark/bigdrive &into /run/media/mark/bigdrive/Archive/sorted.gz

Newbie normally runs in very little memory, the exception is &lookup, which loads a file into RAM and basically does a bulk find and replace on all the matching items. The lookup file must be no larger than about half your available memory.

Dictionary-based lookup and replacement. Create a dictionary file with alternating pattern and replacement lines:
	pattern1
	replacement1
	pattern2
	replacement2

Apply lookups to a file:
	&lookup dict.txt &in data.txt &into replaced.txt

This replaces all occurrences of pattern1 with replacement1, pattern2 with replacement2, etc. The lookup uses the Aho-Corasick algorithm for efficient multi-pattern matching.

Use cases:
- Entity ID to label mapping
- Code to description translation
- Abbreviation expansion
- Any many-to-one string replacement task

FILES AND WILDCARDS

List files in current directory:
	&files

List files in a specific directory:
	&files ~/Documents/

Match files with wildcards:
	&files *.txt
	&files data*.csv &in /data/

COMMON WORKFLOW EXAMPLES

Example 1: Extract and summarize error logs
	&find ERROR &in app.log &into errors.txt
	&show errors.txt &first 20

Example 2: Data extraction pipeline
	&capture ID: &v.id Name: &v.name &in records.txt &write &v.id,&v.name &to output.csv

Example 3: Process multiple files
	&files *.txt &in ~/data/ &run process_script.ns

Example 4: Complex pattern with multiple variables
	&capture &start &= [&v.date] &v.level : &v.message &in system.log &write &v.date | &v.level | &v.message &to structured.txt

Example 5: Conditional data extraction
	&block data.txt
		&v.line &= &newbie.line
		&capture STATUS: &v.status ID: &v.id &in &v.line
		&if &v.status &write &v.id : &v.status &to status_report.txt
	&endblock

ADMINISTRATIVE COMMANDS

Show license:
	&license

Show all variables:
	&vars

Exit Newbie:
	&exit

QUICK REFERENCE TABLE

Command     Purpose              Example
&show       Display file         &show file.txt
&write      Append to file       &write text &to out.txt
&copy       Copy file            &copy a.txt &to b.txt
&move       Move file            &move old.txt &to new.txt
&delete     Delete file/dir      &delete temp.txt
&run        Execute command      &run BASH ls
&find       Pattern search       &find error &in log.txt
&capture    Extract data         &capture &v.id &in data.txt
&block      Process file         &block data.txt ... &endblock
&if         Conditional          &if &v.name &write ... &to file
&not        Negate condition     &not &if &v.x &write ...
&empty      Clear variables      &empty &v.a &v.b
&first      First N lines        &show file.txt &first 10
&last       Last N lines         &show file.txt &last 5
&vars       List variables       &vars
&sort       Sort file            &sort in.txt &into out.txt
&lookup     Dictionary replace   &lookup dict.txt &in data.txt
&convert    Convert format       &convert in.txt &into out.gz
&files      List/match files     &files *.txt
&wrap       Toggle line wrapping &wrap
&admin      Run as sudo          &admin &copy protected &to /etc/
&exit       Quit                 &exit

TROUBLESHOOTING

"No command keywords found"
- Make sure commands start with `&`
- Check for typos in keyword names

Variable not working
- Variables need `&v.` prefix: `&v.name` not `&name`
- Make sure to set before using: `&v.x &= value`

Condition not working
- Empty variables evaluate to false
- Check if variable was cleared: `&empty &v.name`

Block not processing
- Verify file exists: `&if input.txt &write exists &to check.txt`
- Check for `&endblock` closing tag

ADVANCED SCRIPT EXAMPLES

The following examples demonstrate real-world usage of Newbie for complex data processing tasks. I'd like to thank the people at Wikidata, for maintaining latest-truthy.nt.bz2, which gave me an example of a large compressed file to process that I felt legally safe using as an example.

Example 1: Wikidata Processing Pipeline (wdtest.ns)

I've mostly used this example because it is publically available, and a very large file.
This script extracts English-language labels and properties from a compressed Wikidata dump, then performs entity resolution using lookup tables. 
The &find command builds a text file of English language records. I could have parsed the fields directly from the bz2 source, but the &find command is much faster, but less detailed than a &block...&capture...&write...&endblock pattern. Also, bz2 is the slowest of the supported compression algorithms, but it is extremely effective on data like the wikidata n-triples, because it's got a lot of duplication.
The &block then uses &empty and &capture to repopulate the variables, which it then writes to the correct text file.
The &lookup command then loads the lookup.txt file into memory and performs a bulk find and replace using it, on the content of direct-properties.txt, with the output going to WDInEnglish.txt

&show Started: &+   &+ &system.date &+   &+ &system.time
&directory ~/testfolder/
&find &end &= @en . &in /mnt/bigdrive/Archive/latest-truthy.nt.bz2 &into enonly.txt
&block enonly.txt
  &empty &v.label &v.entity &v.direct &v.islabel
  &capture <http://www.wikidata.org/entity/ &+ &v.entity &+ > <http://www.w3.org/2000/01/rdf-schema# &+ &v.islabel &+ > " &+ &v.label &+ "@en .
  &capture <http://www.wikidata.org/entity/ &+ &v.entity &+ > <http://www.wikidata.org/prop/direct/ &+ &v.direct &+ > " &+ &v.label &+ "@en .
  &if &v.islabel &write &v.entity &to lookup.txt
  &if &v.islabel &write &v.label &to lookup.txt
  &if &v.direct &write &v.entity &+   &+ &v.direct &+   &+ &v.label &to direct-properties.txt
&endblock
&lookup lookup.txt &in direct-properties.txt &into WDInEnglish.txt
&show Finished: &+   &+ &system.date &+   &+ &system.time

What this does:
1. Extracts entity IDs and labels using complex patterns from compressed Wikidata English records
2. Builds a lookup dictionary mapping entity IDs to human-readable labels
3. Applies the lookup to replace IDs with labels in the output

Key techniques:
- Working with multi-gigabyte compressed files
- Using &+ for adjacency in complex URI patterns
- Building lookup dictionaries on-the-fly
- Conditional extraction based on RDF predicates

Example 2: Convert RDF to SQL Inserts (tosql.ns)

This script transforms translated Wikidata RDF triples into SQL INSERT statements for database loading. People frequently process bad data in SQL itself, but it's faster to preprocess it with Newbie.

&directory ~/testfolder/
&block enonly.txt
 &empty &v.label &v.entity &v.direct &v.islabel 
  &capture <http://www.wikidata.org/entity/ &+ &v.entity &+ > <http://www.w3.org/2000/01/rdf-schema# &+ &v.islabel &+ > " &+ &v.label &+ "@en .
  &capture <http://www.wikidata.org/entity/ &+ &v.entity &+ > <http://www.wikidata.org/prop/direct/ &+ &v.direct &+ > " &+ &v.label &+ "@en .
 &if &v.islabel &write INSERT INTO entities (entity,label) VALUES (' &+ &v.entity &+ ', ' &+ &v.label &+ '); &to entities.sql
 &if &v.direct &write INSERT INTO properties (entity,direct,label) VALUES (' &+ &v.entity &+ ', ' &+ &v.direct &+ ', ' &+ &v.label &+ '); &to properties.sql
&endblock

What this does:
1. Processes each line of RDF data
2. Captures different triple patterns (labels vs properties)
3. Generates proper SQL INSERT statements with quoted values
4. Separates entity labels and properties into different tables

Key techniques:
- Multiple capture patterns for different triple types
- Variable concatenation with &+ for SQL generation
- Conditional output to multiple files
- Clearing variables between iterations for clean state

Example 3: Comprehensive Test Suite (test.ns)

A complete test suite exercising all Newbie features. Run with: newbie test.ns

The test suite includes 40 tests covering:
- File operations (write, copy, move, delete, show)
- All variable types (user, system, process, network, global, config)
- Conditionals (if, not if, multiple conditions)
- Pattern matching (find with literals, character classes, anchors)
- Data extraction (capture with variables and fences)
- Text processing (first, last, numbered output)
- Compression (convert between formats)
- Advanced features (lookup, sort, block processing)
- Complex workflows (nested blocks with conditionals)

This test suite serves as both validation and a learning resource showing correct syntax for all commands. It also provides a good example of Newbie comments. Note that any line that does not begin with &keyword is a comment. Whitespace is allowed before the &keyword. There is no comment character.

Newbie Test Script - test.ns
Tests implemented features and provides framework for new features

============================================================================
PHASE 1: Basic File Operations (Currently Working)
============================================================================

Test 1: Show first lines of a file
&show Cargo.toml &first 10

Test 2: Show last lines with line numbers
&show src/main.rs &last 20 &numbered

Test 3: List files in current directory
&files

Test 4: List files with sizes
&show &files .

Test 5: List files including hidden
&files &all

============================================================================
PHASE 2: Pattern Matching (Currently Working)
============================================================================

Test 6: Find simple literal pattern
&find TODO &in src/main.rs

Test 7: Find pattern with anchor (if you have test data)
Commented out: &find &end &= Ok(()) &in src/main.rs

Test 8: Find and save to file
Commented out: &find Error &in src/main.rs &into errors.txt

============================================================================
PHASE 3: External Commands (Currently Working)
============================================================================

Test 9: Silent execution
&run &bash echo "This won't be visible"

Test 10: Visible execution
&show &run &bash echo "This will be visible"

Test 11: More complex bash command
&show &run &bash ls -lah | head -5

Test 12: Create a test file with bash
&run &bash echo "Line 1\nLine 2\nLine 3" > newbie_test.txt

Test 13: Show the created file
&show newbie_test.txt

============================================================================
PHASE 4: Compression (Currently Working)
============================================================================

Test 14: Create and compress a test file
&run &bash echo "Test data for compression" > /tmp/test_source.txt
&convert test_source.txt &into test_compressed.gz

Test 15: Show compressed file (should decompress transparently)
&show test_compressed.gz

Test 16: Convert between compression formats
&convert test_compressed.gz &into test_compressed.bz2

============================================================================
PHASE 5: File Operations (Currently Working)
============================================================================

Test 17: Copy a file
&copy newbie_test.txt &to newbie_test_copy.txt

Test 18: Move/rename a file
&move newbie_test_copy.txt &to newbie_test_renamed.txt

Test 19: Show the moved file
&show newbie_test_renamed.txt

============================================================================
PHASE 6: Variable System (Currently Working)
============================================================================

Test 20: Set and get a variable
&v.testvar &= Hello from Newbie
&show &v.testvar

Test 21: List all variables
&vars

Test 22: Show system variables
&vars system

============================================================================
PHASE 7: Block Processing 
============================================================================

Test 23: Simple line-by-line processing
Note that &newbie.line is always populated by the current line in the block
&block newbie_test.txt
  &empty &v.line
  &v.line &= &newbie.line
  &write Line: &v.line &to processed.txt
&endblock

Test 24: Pattern capture and conditional output
&block newbie_test.txt
  &empty &v.num
  &v.num &= 56
  &if &v.num &write Found number: &v.num &to filtered.txt
&endblock

Test 25: Multiple output files
&block newbie_test.txt
  &empty &v.line &v.num
  &v.line &= &newbie.line
  &v.num &= 24
  &write &v.line &to lines.txt
  &if &v.num &write &v.num &to numbers.txt
&endblock

Test 26: Accumulation with &append
&block newbie_test.txt
  &empty &v.line
  &v.line &= &newbie.line
  &write &v.line &to accumulated.txt
&endblock

# ============================================================================
# CLEANUP
# ============================================================================

# Test 27: Delete test files
&delete newbie_test.txt
&delete test_source.txt
&delete test_compressed.gz
&delete newbie_test_renamed.txt
&delete processed.txt
&delete filtered.txt
&delete lines.txt
&delete numbers.txt
&delete accumulated.txt



Happy scripting!

---

Newbie 1.0 - ©2025 Mark Allen Battey - MIT License
