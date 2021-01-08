# Regular expressions

## Intro

There are two ways to test your expressions. Either:

1. create a text file with some test paragraphs (in a Unix machine) and then use `egrep <pattern> <file>` to see what matches and what doesn't.

2. use an online editor like [this](https://regexr.com/). You can add your own text in the "Text" field, and then type your expressions (patterns) in the "Expression" field.

## Charsets

When searching for a specific string in a file or block of text, you can search for it as is, with `grep 'string' <file>` . But what happens if you want to search for **patterns of text**? For example, you could be looking for a word that starts with a specific letter, or any words that end with numbers. That's where Regular Expressions come in.

Both of the aforementioned problems can be solved by using **charsets**. A charset is defined by enclosing in `[` square brackets `]` the character(s), or range of characters that you want to match.  Then, it finds every occurrence of the pattern you have defined in the file/text you are searching.

`[abc]` will match `a`, `b`, and `c` (every occurrence of each letter)

`[abc]zz` will match `azz`, `bzz`, and `czz`.

You can also use a `-` dash to define ranges:
`[a-c]zz` is the same as above.

And then you can combine ranges together:
`[a-cx-z]zz` will match `azz`, `bzz`, `czz`, `xzz`, `yzz`, and `zzz`.

Most notably, this can be used to match any alphabetical character:
`[a-zA-Z]` will match any **single** letter (lowercase or uppercase).

You can use numbers too:
`file[1-3]` will match `file1`, `file2`, and `file3`.

Then, there is a way to **exclude** characters from a charset with the `^` hat symbol, and include everything else.
`[^k]ing` will match `ring`, `sing`, `$ing`, but not `king`.

Of course, you can exclude charsets, not just single characters.
`[^a-c]at` will match `fat` and `hat`, but not `bat` or `cat`.

**Note 1**: Don't confuse strings with charsets. The charset `[abc]` will match the string `abc`, but also `cba` and `ca`. It doesn't match the string, but rather **every occurrence** of the specified characters in that string.

**Note 2**: When specifying charsets, you should type the letters in the same order they appear in the questions, to avoid typing something correct that is not the right answer.

**Note 3**: **Answering some of these questions is going to be tricky**. Often times there are many different patterns that match specific strings. That means (as stated in the previous note) that you may find a proper solution that isn't the right answer for this room (because there can only be one). The right answer is typically the most efficient regex for that question. Efficient in this context means 2 things:
    1. **Be specific**. Here's an example: you could match any character from a to c using the `[a-z]` charset. But if the question only requires you to match characters from `a` to `c`, you should use the `[a-c]` charset, not `[a-z]`.
    2. **Don't be too specific**. In contrast to the previous example, if a question requires you to match `a`, `c`, `f`, `r`, `s`, `z`, at that point, the expression that matches those specific characters would get longer and more complicated. So, it would make more sense to use `[a-z]`, because it is short and simple.

To reiterate, **there cannot be one single correct solution**. So if you've tested your solution and it works, you can take a break and come back to it later, or ask for a hint in discord, but try not to get frustrated.

## Wildcards and optional characters

The wildcard that is used to match any single character (except the line break) is the `.` dot. That means that `a.c` will match `aac`, `abc`, `a0c`, `a!c`, and so on.

Also, you can set a character as optional in your pattern using the `?` question mark. That means that `abc?` will match `ab` and `abc`, since the `c` is optional.

Note: If you want to search for `.` a literal dot, you have to **escape it** with a `\` reverse slash. That means that `a.c` will match `a.c`, but also `abc`, `a@c`, and so on. But `a\.c` will match just `a.c`.

## Metacharacters and repetitions

There are easier ways to match bigger charsets. For example, `\d` is used to match any **single** digit. Here's a reference:
`\d` matches a digit, like `9`
`\D` matches a non-digit, like `A` or `@`
`\w` matches an alphanumeric character, like `a` or `3`
`\W` matches a non-alphanumeric character, like `!` or `#`
`\s` matches a whitespace character (spaces, tabs, and line breaks)
`\S` matches everything else (alphanumeric characters and symbols)

Note: Underscores `_` are included in the `\w` metacharacter and not in `\W`. That means that `\w` will match every single character in `test_file`.

Often we want a pattern that matches many characters of a single type in a row, and we can do that with repetitions. For example, `{2}` is used to match the preceding character (or metacharacter, or charset) two times in a row. That means that `z{2}` will match exactly `zz`.

Here's a reference for each repetition along with how many times it matches the preceding pattern:

`{12}` - **exactly 12** times.
`{1,5}` - **1 to 5** times.
`{2,}` - **2 or more** times.
`*` - **0 or more** times.
`+` - **1 or more** times.

## Starts with/ ends with, groups, and either/ or

Sometimes it's very useful to specify that we want to search by a certain pattern in the beginning or the end of a line. We do that with these characters:
`^` - starts with
`$` - ends with

So for example, if you want to search for a line that **starts with** `abc`, you can use `^abc`.
If you want to search for a line that ends with `xyz`, you can use `xyz$`.

Note: The `^` hat symbol is used to exclude a charset when enclosed in `[` square brackets `]`, but when it is not, it is used to specify the beginning of a word.

You can also define groups by enclosing a pattern in `(` parentheses `)`. This function can be used for many ways that are not in the scope of this tutorial. We will use it to define an **either/ or** pattern, and also to repeat patterns. To say "or" in Regex, we use the `|` pipe.

For an "either/or" pattern example, the pattern `during the (day|night)` will match both of these sentences: `during the day` and `during the night`.
For a repetition example, the pattern `(no){5}` will match the sentence `nonononono`.
