---
title: Simple shell with Go
summary: What is a shell? What does it do? How does it work?
---

After taking CS 377 Operating systems, one of the projects that left an impression was the first and arguably the hardest project: a simple shell which includes pipes

With the goal of learning, I decided to attempt to reimplement the project with a different language [Go](https://go.dev/)

## So, what is a shell anyways?

The shell comes in many different varieties including sh, bash, zsh, fish and many other more. The shell itself, is a program that allows the user to interact with the underlying operating system, including the kernel, thus the meaning of "shell" is like the shell that encapsulates the kernel.

## Okay enough explaining, what code do I need to write?

### Before that, let's think about what a shell needs to do, from a high level

What happens when you type something into the terminal, for example "ls"?

```sh {linenos=false}
leon3@t1600:~/cs377$ ls -l 
drwxr-xr-x 1 leon3 leon3      0 Mar 26 14:24 377-lab-fork-exec     
drwxr-xr-x 1 leon3 leon3    218 Jul 24 01:47 project1-shell        
drwxr-xr-x 1 leon3 leon3     22 Jul 26 02:10 project1-shell-go     
drwxr-xr-x 1 leon3 leon3     58 Jul 24 01:11 project1-shell-rs     
-rw-r--r-- 1 leon3 leon3   8021 Mar 26 14:24 project1-shell.zip    
drwxr-xr-x 1 leon3 leon3    124 Mar 26 14:24 project2-scheduler    
-rw-r--r-- 1 leon3 leon3 327650 Mar 26 14:24 project2-scheduler.zip
drwxr-xr-x 1 leon3 leon3    200 Jul 24 01:09 project3-banking      
-rw-r--r-- 1 leon3 leon3 249434 Mar 26 14:24 project3-banking.zip  
drwxr-xr-x 1 leon3 leon3     44 Jul 24 01:09 project4-allocator
```

It prints out all the files in the current directory

The shell:

- Takes in user input for the command and it's arguments, here it would be "ls" as the command, "-l" as the argument
- Executes the command with argument, in this case "ls" is a binary that is part of the core functionality of the OS
- The shell then writes the output back to the user

Now let's look at a different example that includes "|", the pipe sign

```sh {linenos=false}
leon3@t1600:~/cs377$ ls -l|grep shell
drwxr-xr-x 1 leon3 leon3    218 Jul 24 01:47 project1-shell
drwxr-xr-x 1 leon3 leon3     22 Jul 26 02:10 project1-shell-go
drwxr-xr-x 1 leon3 leon3     58 Jul 24 01:11 project1-shell-rs
-rw-r--r-- 1 leon3 leon3   8021 Mar 26 14:24 project1-shell.zip
```

Here we run "ls" again, and the "grep" command filters out for the specific pattern "shell"

#### But what does the "|" do? What is a pipe?

Simply put, a pipe allows two programs in the OS to communicate in one direction, kind of like a letter in real life.

Recall that on Linux, generally each process have 3 standard file descriptors:

```text {linenos=false}
--------------
| 0 | stdin  |
| 1 | stdout |
| 2 | stderr |
--------------
```

In this case, when using the "|" sign, you are telling the shell to create a pipe so that the first command can communicate to the second command, connecting the `stdout` of the first to the `stdin` of the second process. This also creates an execution chain because the result of the second command will depend on the result of the first command.

#### Let's make a more complete list of things that out simple shell needs to do

- Print prompt
- Takes in user input by using a function like "fgets"
- Parse the input into command and arguments by splitting, using function like "strtok"
- Factoring in delimiters like ";" to end the execution chain or the "|" sign to determine if we need to create pipes
- Create the necessary resources including pipes and duplicating file descriptors, using syscalls like "fork" and "dup"

### Let's do some coding

#### Printing prompt

Let's use `fmt.Printf(">")`

```go
package main

import "fmt"

func printPrompt() {
    fmt.Printf(">")
}
```

#### Getting user input

There are a few ways to get user input in Go, we could use scanf, however in this case, we don't have a specific format, so we can read from stdin, conveniently, Go also offer the "bufio" package, which includes functions related to bufferd io. In this case, we can use the "reader" type to read from stdin.

Using the `Readstring` method, it reads until the first occurrence of delimiter in the input, returning a string containing the data up to and including the delimiter.

So, in order to read the line, we use the new line character `'\n'` as the delimiter for `Readstring`.

Adding these together, we can form a loop that prints the prompt, then reads the user input until a new line.

```go
for {
    printPrompt()
    line, err := reader.ReadString('\n')
}
```

Now we have the input line, we need to parse the line into command and arguments, including the delimiters ";" and "|". How do we do that?

Let's use an example:

`ls -l|grep project|grep 1;cat 1.txt|grep hello;uname;uname`

Each semicolon denotes that the command chain before it and after it are independent of each other, this means that this example can be split into 4 different independent command chains.

`ls -l|grep project|grep 1`
`cat 1.txt|grep hello`
`uname`
`uname`

We can define a data structure to represent each command

```go
type Process struct {
    Cmd      string // the executable name 
    Args     []string // the full command
    pipe_in  bool // if the command need to read from a pipe
    pipe_out bool // if the command need to write to a pipe
    pipe_r   *os.File // the pipe read end
    pipe_w   *os.File // the pipe write end
    execCmd  *exec.Cmd // pointer to the Cmd structure used by exec module
}
```

#### Parsing input

Now let's tackle the first chain, which includes 3 pipe symbols.

The first command `ls`, does not read from a pipe. The last command `grep 1` does not write to a pipe, we know that for every command seperated by the pipe sign, they are all dependent, we can assume that they both pipe in and pipe out.

We can use a nested loop to handle this

```go
cmd_indep := strings.Split(line, ";")
for _, indep := range cmd_indep {
    cmd_pipes := strings.Split(indep, "|")
    for idx, dep_cmds := range cmd_pipes {
        // create data structure
        currProcess := Process{}
        args := strings.Fields(dep_cmds)
        // split the command it self into the executable and the arguments 
        currProcess.Cmd = args[0]
        if len(args) > 1 {
                currProcess.Args = args[1:]
        } // assign the full args to the struct

        currProcess.pipe_out = true 
        if idx == len(cmd_pipes) - 1 { // if it's the last command in the chain, do not pipe out
            currProcess.pipe_out = false
        }

        currProcess.pipe_in = false
        if idx > 0 { // if it's the second or later command, accept input from pipe
            currProcess.pipe_in = true
        }
}
```

Adding add the created processes to a list, we have a list of processes to be executed after being parsed.

#### Setting up process abstractions

In C, we would use `execvp` to run an executable after using `fork`. Now to achieve the same thing in Go, we can utilize the [exec](https://pkg.go.dev/os/exec) package.

First we can use the `exec.Command` function to create a representation of the command to be executed. Then according to the [documentation](https://pkg.go.dev/os/exec#Command) `It sets only the Path and Args in the returned structure.` This means that we need to assign values to some other fields in order to achieve piping. There are two fields that we are particularly interested in `Stdin` and `Stdout`

Let's write a loop to create these structures

```go
// command list is a list of Process struct
for _, currCmd := range command_list { 
    currExec := exec.Command(currCmd.Cmd, currCmd.Args...)
    ...
}
```

Where `currCmd` is the `Process` struct described earlier, and `currExec` is the struct used by the `exec` package.

#### Creating Pipes

To create a pipe, we use the `os.Pipe()` method, which similar to the `pipe` syscall, returns a read end and a write end.

```go
pr, pw, _ := os.Pipe() // 3 returns, ignoring error handling here
```

Then, if this command needs to pipe out, we assign the write end to the `Stdout`, otherwise we want to inherit the stdout from the shell process itself, to access that we use `os.Stdout`

```go
currExec.Stdout = os.Stdout
if currCmd.pipe_out {
    pr, pw, _ := os.Pipe()
    currExec.Stdout = pw
}
```

#### Assigning pipes

Now how do we connect the read end of the pipe to the next command? To achieve this we can use a `prev` variable to keep track of the previous pipe read end, we want to inherit the underlying stdin and if the current command needs to pipe in, assign the read end to `Stdin`.

```go
currExec.Stdin = os.Stdin
if currCmd.pipe_in && prev != nil {
    currExec.Stdin = prev.pipe_r
} 
```

#### Running the command, and cleaning up at the end

Finally, we can call `currExec.start()` to start the command.

Note that similar to C, we also need to call `wait` to clean up the associated resources so the terminated process does not become zombie, to do that, we can add each `currCmd` into a list, then loop over it to call `currCmd.Wait()` Finally, just like the C version, close all the associated pipe ends.

```go
var waitList []Process // the struct we created
currExec.Start()

waitList = append(waitList, currCmd)

for _, cmd := range waitList {
    cmd.execCmd.Wait() // use the reference to the "exec" struct
    cmd.pipe_w.Close() // then access the pipe file to close it
}
```

This may seem really confusing at first, because I have used a nested data structure here, however, I believe that this is the simplest way to extend an abstraction for it to fit the need of the project.

Check out the source code of the project on [GitHub](https://github.com/leon332157/go-toys/blob/main/simple-shell/main.go)
