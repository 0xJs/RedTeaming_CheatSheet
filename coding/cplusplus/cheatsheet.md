# C++ Cheatsheet
- https://www.w3schools.com/cpp/default.asp
- https://www.codecademy.com/learn/paths/learn-c-plus-plus/tracks/learn-c-plus-plus/modules/learn-cpp-hello-world/cheatsheet

# C++ Syntax
```c++
#include <iostream>  
using namespace std;  
  
int main() {  
  cout << "Hello World!";  
  return 0;  
}
```

- **Line 1:** `#include <iostream>` is a **header file library** that lets us work with input and output objects, such as `cout` (used in line 5). Header files add functionality to C++ programs.
- **Line 2:** `using namespace std` means that we can use names for objects and variables from the standard library.
	- Don't worry if you don't understand how `#include <iostream>` and `using namespace std` works. Just think of it as something that (almost) always appears in your program.
- **Line 3:** A blank line. C++ ignores white space. But we use it to make the code more readable.
- **Line 4:** Another thing that always appear in a C++ program, is `int main()`. This is called a **function**. Any code inside its curly brackets `{}` will be executed.
- **Line 5:** `cout` (pronounced "see-out") is an **object** used together with the _insertion operator_ (`<<`) to output/print text. In our example it will output "Hello World".
	- **Note:** Every C++ statement ends with a semicolon `;`.
	- **Note:** The body of `int main()` could also been written as: `int main () { cout << "Hello World! "; return 0; }`
- **Line 6:** `return 0` ends the main function.
- **Line 7:** Do not forget to add the closing curly bracket `}` to actually end the main function.

# Output
```c++
#include <iostream>  
using namespace std;  
  
int main() {  
  **cout** << "Hello World!";  
  return 0;  
}
```

# Comments
## Single line
```csharp
// This is a comment
cout << "Hello World!";

cout << "Hello World!";  // This is a comment
```

## Multiple lines
```
/* The code below will print the words Hello World
to the screen, and it is amazing */
Console.WriteLine("Hello World!"); 
```

# Variables
-   `int` - stores integers (whole numbers), without decimals, such as 123 or -123
-   `double` - stores floating point numbers, with decimals, such as 19.99 or -19.99
-   `char` - stores single characters, such as 'a' or 'B'. Char values are surrounded by single quotes
-   `string` - stores text, such as "Hello World". String values are surrounded by double quotes
-   `bool` - stores values with two states: true or false

```c++
int myNum = 5;               // Integer (whole number without decimals)  
double myFloatNum = 5.99;    // Floating point number (with decimals)  
char myLetter = 'D';         // Character  
string myText = "Hello";     // String (text)  
bool myBoolean = true;       // Boolean (true or false)
```

# Operators
## Comparison
```c++
== Equal to
!= Not Equal
> Greater than
< Less than
>= Greather than or equal to
<= Less than or equal to
```

## Logical
```c++
&& Logial and - Returns True if both statements are true
|| Logical or - Returns True if one of the statements is true
! Logical not - Reverse the result, returns False if the result is true
```

# User Input
Uses `cin`

```c++
int x;   
cout << "Type a number: "; // Type a number and press enter  
cin >> x; // Get user input from the keyboard  
cout << "Your number is: " << x; // Display the input value
```

# If statement

```c++
if (condition) 
{
  // block of code to be executed if the condition is True
}
```

```c++
if (condition1)
{
  // block of code to be executed if condition1 is True
} 
else if (condition2) 
{
  // block of code to be executed if the condition1 is false and condition2 is True
} 
else
{
  // block of code to be executed if the condition1 is false and condition2 is False
}
```

# While loop
```c++
while (condition) 
{
  // code block to be executed
}

// EXAMPLE
int i = 0;
while (i < 5) 
{
  cout << i << "\n";
  i++;
}
```

## Do while
```c++
do {
  // code block to be executed
}
while (condition);

int i = 0;  
do {  
  cout << i << "\n";  
  i++;  
}  
while (i < 5);
```

# For loop
```c++
for (statement 1; statement 2; statement 3) 
{
  // code block to be executed
}

// EXAMPLE
for (int i = 0; i < 5; i++) 
{
  cout << i << "\n";
}
```

# Errors
- Syntax errors: Errors that occur when we violate the rules of C++ syntax.
	- Some common syntax errors are:
		- Missing semicolon `;`
		- Missing closing parenthesis `)`, square bracket `]`, or curly brace `}`
- Type errors: Errors that occur when there are mismatch between the types we declared.
	- Some common type errors are:
		-   Forgetting to declare a variable
		-   Storing a value into the wrong type
- Link-time errors: Sometimes the code compiles fine, but there is still a message because the program needs some function or library that it can’t find.
	- Some common link-time erros:
		- Using a function that was never defined (more on this later)
		- Writing `Main()` instead of `main()`
- Run-time errors:  Run-time errors occur when a program with no compile-time errors and link-time errors asks the computer to do something that the computer is unable to reliably do.
	- Some common run-time errors:
		- Division by zero also known as _division error_. These types of error are hard to find as the compiler doesn’t point to the line at which the error occurs.
		- Trying to open a file that doesn’t exist
- Logic errors: errors which provide incorrect output, but appears to be error-free, are called logical errors.
	- Some common logic errors:
		- Program logic is flawed
		- Some “silly” mistake in an `if` statement or a `for`/`while` loop

# Vectors
- A _vector_ is a sequence of elements that you can access by index. `#include <vector>`

```c++
std::vector<type> name;

std::vector<int> calories_today;
std::vector<double> location;
```

Initialize a vector:
```c++
# With values
std::vector<double> location = {42.651443, -73.749302};

# Without values
std::vector<double> location(2);
```

Print vector based on index:
```c++
std::cout << location[0] << "\n";
```

Adding and removing to vector:
```c++
std::vector<std::string> dna = {"ATG", "ACG"};

# ADD AT THE END
dna.push_back("GTG");
dna.push_back("CTG");

# RESULTS
std::vector<std::string> dna = {"ATG", "ACG", "GTG", "CTG"};

# REMOVE ELEMENT FROM THE BACK
dna.pop_back();
```

# Functions
- Function without a return type is a void
```c++
voic car {
 
   // Code block here
   std:cout << "Car";
 
}
```

- When writing a function that returns something the syntax is:
```c++
return_type function_name( any, parameters, you, have ) {
 
   // Code block here
 
   return output_if_there_is_any;
 
}

# EXAMPLE
stdd::string Cars(std::string car, int amount) {
	int price = car * amount;
	// Code block here
 
	return price;
	
}
```

## Ordering functions
- Place functions is a seperate `.cpp` file. Example: `fns.cpp`
- Add a header file with the same name as the functions file but with the `.hpp` extension. Example: `fns.hpp`
- Add it as an header and include it. Example: `#include "fns.hpp"`

## Inline functions
Using `inline` advises the compiler to insert the function’s body where the function call is, which sometimes helps with execution speed (and sometimes hinders execution speed). If you do use it, we recommend testing how it affects the execution speed of your program. The bottom line is `inline` is something you’ll probably encounter, but may never use.

```c++
inline 
void eat() {
 
  std::cout << "nom nom\n";
 
}
```

## Default value for arguments
- if you leave the argument blank in your function call, instead of an error, your function will run with the default value.

```c++
// Declaration
void intro(std::string name, std::string lang = "C++");
 
// Definition
void intro(std::string name, std::string lang) {
  std::cout << "Hi, my name is "
            << name
            << " and I'm learning "
            << lang
            << ".\n";
}
```

## Function overloading
- But better to use templates!

In a process known as function overloading, you can give multiple C++ functions the same name. Just make sure at least one of these conditions is true:
-   Each has different type parameters.
-   Each has a different number of parameters.

```c++
void print_cat_ears(char let) {
  std::cout << " " << let << "   " << let << " " << "\n";
  std::cout << let << let << let << " " << let << let << let << "\n";
}
 
void print_cat_ears(int num) {
  std::cout << " " << num << "   " << num << " " << "\n";
  std::cout << num << num << num << " " << num << num << num << "\n";
}
```

### Templates
- Unlike regular functions, templates are entirely created in header files.

```c++
template <typename T>
void print_cat_ears(T item) {
 
  std::cout << " " << item << "   " << item << " " << "\n";
  std::cout << item << item << item << " " << item << item << item << "\n";
}
```

# Scope
Scope is the region of code that can access or view a given element.
-   Variables defined in global scope are accessible throughout the program.
-   Variables defined in a function have local scope and are only accessible inside the function.

# Classes
- A C++ class is a user-defined type.
- There are two types of class members:
	- Attributes, also known as member data, consist of information about an instance of the class.
	- Methods, also known as member functions, are functions that you can use with an instance of the class. We use a `.` before method names to distinguish them from regular functions.
```c++
class City {
 
  // attribute
  int population;
 
public:
  // method
  void add_resident() {
    population++;
  }
 
}; // <-- notice this semicolon!
```

- Unless we have a mostly empty class, it’s common to split function declarations from definitions. We declare methods inside the class (in a header), then define the methods outside the class (in a **.cpp** file of the same name).
- How can we define methods outside a class? We can do this using `ClassName::` before the method name to indicate its class like this:
```c++
int City::get_population() {
  return population;
}
```

### Example
#### Music.cpp
```c++
#include <iostream>
#include "song.hpp"

int main() {

}
```

#### song.hpp
```c++
#include <string>

// add the Song class here:
class Song {
  
  std::string title;

public:
  void add_title(std::string new_title);
  std::string get_title();
  
};
```

#### song.cpp
```c++
#include "song.hpp"

// add Song method definitions here:
void Song::add_title(std::string new_title) {

  title = new_title;

}

std::string Song::get_title() {

  return title;

}
```

## Objects
- An object is an instance of a class, which encapsulates data and functionality pertaining to that data.

```c++
// Create object
City accra;

// Give value
accra.population = 2270000;

// Access information
accra.get_population();
```

### Example
#### Music.cpp
```c++
#include <iostream>
#include "song.hpp"

int main() {
  // Create (instansiate) an object
  Song electric_relaxation;

  // Call the add_title function of the obect and add title
  electric_relaxation.add_title("Electric Relaxation");

  // Call the get_title function and retrieve the title to the variable title
  std::string title = electric_relaxation.get_title();
  std::cout << title;
}
```

#### song.hpp
```c++
#include <string>

// add the Song class here:
class Song {
  
  std::string title;

public:
  void add_title(std::string new_title);
  std::string get_title();
  
};
```

#### song.cpp
```c++
#include "song.hpp"

// add Song method definitions here:
void Song::add_title(std::string new_title) {

  title = new_title;

}

std::string Song::get_title() {

  return title;

}
```


## Access Control Public and Private
- By default, everything in a class is `private`, meaning class members are limited to the scope of the class.
- Can be set to public using `public:` like in the example above.
- If a function should be private then `private:` can be used.

## Constructors
- A constructor is a special kind of method that lets you decide how the objects of a class get created.
- It has the same name as the class and no return type. Constructors really shine when you want to instantiate an object with specific attributes.

```c++
// city.hpp
#include "city.hpp"
 
class City {
 
  std::string name;
  int population;
 
public:
  City(std::string new_name, int new_pop);
 
};
 
// city.cpp
City::City(std::string new_name, int new_pop)
  // members get initialized to values passed in 
  : name(new_name), population(new_pop) {}
```

Then iniate an object:
```c++
// inside main()
City ankara("Ankara", 5445000);
```

### Example
#### Music.cpp
```c++
#include <iostream>
#include "song.hpp"

int main() {

  Song back_to_black("Back to Black", "Amy Winehouse");
  
  std::cout << back_to_black.get_title() << "\n";
  std::cout << back_to_black.get_artist() << "\n";
  
}
```

#### song.hpp
```c++
#include <string>

class Song {
  
  std::string title;
  std::string artist;

public:
  // Add a constructor here:
  Song(std::string new_title, std::string new_artist);
  
  std::string get_title();
  
  std::string get_artist();
  
};
```

#### song.cpp
```c++
#include "song.hpp"

// add the Song constructor here:
Song::Song(std::string new_title, std::string new_artist)
  : title(new_title), artist(new_artist){}

std::string Song::get_title() {

  return title;

}

std::string Song::get_artist() {

  return artist;

}
```

## Destructors
- is preceded by a `~` operator and takes no parameters.

```c++
// city.hpp
class City {
 
  std::string name;
  int population;
 
public:
  City(std::string new_name, int new_pop);
  ~City();
};
 
// city.cpp
City::~City() {
 
  // any final cleanup
 
}
```

### Example
#### Music.cpp
```c++
#include <iostream>
#include "song.hpp"

int main() {

  Song back_to_black("Back to Black", "Amy Winehouse");
    
}
```

#### song.hpp
```c++
#include <string>

class Song {
  
  std::string title;
  std::string artist;

public:
  Song(std::string new_title, std::string new_artist);
  // Add a destructor here:
  ~Song();
  
  std::string get_title();
  
  std::string get_artist();
  
};
```

#### song.cpp
```c++
#include "song.hpp"
#include <iostream>

Song::Song(std::string new_title, std::string new_artist) 
  : title(new_title), artist(new_artist) {}

// add the Song destructor here:
Song::~Song () {
  std::cout << "Goodbye " << title;
}

std::string Song::get_title() {

  return title;

}

std::string Song::get_artist() {

  return artist;

}
```

# References and Pointers
## References
- In C++, a reference variable is an alias for something else, that is, another name for an already existing variable.
- We can create an alias to it by using the `&` sign in the declaration

```c++
int &sonny = songqiao;
```

### Pass by reference
Pass-by-reference refers to passing parameters to a function by using references. When called, the function can modify the value of the arguments by using the reference passed in.

This allows us to:
-   Modify the value of the function arguments.
-   Avoid making copies of a variable/object for performance reasons.

The following code shows an example of pass-by-reference. The reference parameters are initialized with the actual arguments when the function is called:

```c++
void swap_num(int &i, int &j) {
 
  int temp = i;
  i = j;
  j = temp;
 
}
 
int main() {
 
  int a = 100;
  int b = 200;
 
  swap_num(a, b);
 
  std::cout << "A is " << a << "\n";
  std::cout << "B is " << b << "\n";
 
}
```

- using references as parameters allows us to modify the arguments’ values. This can be very useful in a lot cases.

## Memory address
- The “address of” operator, `&`, is used to get the memory address, the location in the memory, of an object.

```c++
#include <iostream>

int main() {
  
  int power = 9000;
  
  // Print power
  std::cout << power << "\n";
  
  // Print adress &power
  std::cout << &power << "\n";
  
}
```

## Pointers
- In C++, a _pointer_ variable is mostly the same as other variables, which can store a piece of data. Unlike normal variables, which store a value (such as an `int`, `double`, `char`), a pointer stores a memory address.
- avoid pointers as much as possible; usually, a reference will do the trick. However, you will see pointers a lot in the wild, particularly in older projects, where they are used in a very similar way to references.
- They are syntactically distinguished by the `*`, so that `int*` means “pointer to `int`“ and `double*` means “pointer to `double`“.

```c++
#include <iostream>

int main() {
  
  int power = 9000;
  
  // Create pointer
  int* ptr = &power;
  
  // Print ptr
  std::cout << ptr << "\n";
  
}
```

## Dereference
- The asterisk sign `*` a.k.a. the dereference operator is used to obtain the value pointed to by a variable. This can be done by preceding the name of a pointer variable with `*`.
- The double meaning of the `*` symbol can be tricky at first, so make sure to note:
	- When `*` is used in a declaration, it is creating a pointer.
	- When `*` is not used in a declaration, it is a dereference operator.

```c++
#include <iostream>

int main() {
  
  int power = 9000;
  
  // Create pointer
  int* ptr = &power;
  
  // Print ptr
  std::cout << ptr << "\n";
  
  // Print *ptr
  std::cout << *ptr << "\n";
  
}
```

## Null Pointer
- When we declare a pointer variable like so, its content is not intialized: `int* ptr;`
- In other words, it contains an address of “somewhere”, which is of course not a valid location. This is [dangerous](https://en.wikipedia.org/wiki/Uninitialized_variable)! We need to initialize a pointer by assigning it a valid address.
- We can use `nullptr` like so: `int* ptr = nullptr;`

# Compiling
### Run the command
```
g++ main.cpp
```

#### When multiple cpp files
```
g++ main.cpp fns.cpp
```
