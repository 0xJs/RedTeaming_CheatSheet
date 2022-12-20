# C# cheatsheet
- https://www.w3schools.com/cs/index.php
- https://www.codecademy.com/learn/learn-c-sharp/modules/csharp-hello-world/cheatsheet

# General
- Press F12 in visual studio code to go to the definition of the API for example.
- Press F1 in visual studio code to open the help page of the definition.
- Shortcut overview: https://visualstudio.microsoft.com/keyboard-shortcuts.pdf

# C# Syntax
```csharp
using System;

namespace HelloWorld
{
  class Program
  {
    static void Main(string[] args)
    {
      Console.WriteLine("Hello World!");    
    }
  }
}
```

- **Line 1:** `using System` means that we can use classes from the `System` namespace.
- **Line 2:** A blank line. C# ignores white space. However, multiple lines makes the code more readable.
- **Line 3:** `namespace` is used to organize your code, and it is a container for classes and other namespaces.
- **Line 4:** The curly braces `{}` marks the beginning and the end of a block of code.
- **Line 5:** `class` is a container for data and methods, which brings functionality to your program. Every line of code that runs in C# must be inside a class. In our example, we named the class Program.
	- Don't worry if you don't understand how `using System`, `namespace` and `class` works. Just think of it as something that (almost) always appears in your program, and that you will learn more about them in a later chapter.
- **Line 7:** Another thing that always appear in a C# program, is the `Main` method. Any code inside its curly brackets `{}` will be executed. You don't have to understand the keywords before and after Main. You will get to know them bit by bit while reading this tutorial.
- **Line 9:** `Console` is a class of the `System` namespace, which has a `WriteLine()` method that is used to output/print text. In our example it will output "Hello World!".
	- If you omit the `using System` line, you would have to write `System.Console.WriteLine()` to print/output text.
- **Note:** Every C# statement ends with a semicolon `;`.
- **Note:** C# is case-sensitive: "MyClass" and "myclass" has different meaning.
- **Note:** Unlike [Java](https://www.w3schools.com/java/default.asp), the name of the C# file does not have to match the class name, but they often do (for better organization). When saving the file, save it using a proper name and add ".cs" to the end of the filename. To run the example above on your computer, make sure that C# is properly installed: Go to the [Get Started Chapter](https://www.w3schools.com/cs/cs_getstarted.php) for how to install C#. The output should be:

# Output
```csharp
Console.WriteLine("Hello World!");
Console.WriteLine("I am Learning C#");
Console.WriteLine("It is awesome!");
```

# Comments
## Single line
```csharp
// This is a comment
Console.WriteLine("Hello World!");

Console.WriteLine("Hello World!");  // This is a comment
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
-  Can also create arrays, for example `string[] myStringArray = {"line1", "line2"}` or `int[] myNum = {10, 20, 30, 40};`

```csharp
int myNum = 5;               // Integer (whole number)
double myDoubleNum = 5.99D;  // Floating point number
char myLetter = 'D';         // Character
string myText = "Hello";     // String
bool myBool = true;          // Boolean
``` 

# Operators
## Comparison
```
== Equal to
!= Not Equal
> Greater than
< Less than
>= Greather than or equal to
<= Less than or equal to
```

## Logical
```
&& Logial and - Returns True if both statements are true
|| Logical or - Returns True if one of the statements is true
! Logical not - Reverse the result, returns False if the result is true
```

# User input
Can be requested with Console.ReadLine();

```csharp
// Type your username and press enter
Console.WriteLine("Enter username:");

// Create a string variable and get user input from the keyboard and store it in the variable
string userName = Console.ReadLine();

// Print the value of the variable (userName), which will display the input value
Console.WriteLine("Username is: " + userName);
```

# If Statement
```csharp
if (condition) 
{
  // block of code to be executed if the condition is True
}
```

```csharp
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

## Switch statement
```csharp
string color;
 
switch (color)
{
   case "blue":
      // execute if the value of color is "blue"
      Console.WriteLine("color is blue");
      break;
   case "red":
      // execute if the value of color is "red"
      Console.WriteLine("color is red");
      break;
   case "green":
      // execute if the value of color is "green"
      Console.WriteLine("color is green");
      break;
   default:
      // execute if none of the above conditions are met
      break;
}
```

## Ternary Operators
```Csharp
string color = "blue";
string result = (color == "blue") ? "blue" : "NOT blue";
 
Console.WriteLine(result);
```

# While loop
```csharp
while (condition) 
{
  // code block to be executed
}

// EXAMPLE
int i = 0;
while (i < 5) 
{
  Console.WriteLine(i);
  i++;
}
```

## Do while
```csharp
do 
{
  // code block to be executed
}
while (condition);

// EXAMPLE
int i = 0;
do 
{
  Console.WriteLine(i);
  i++;
}
while (i < 5);
```

# For loop
```csharp
for (statement 1; statement 2; statement 3) 
{
  // code block to be executed
}

// EXAMPLE
for (int i = 0; i < 5; i++) 
{
  Console.WriteLine(i);
}
```

## Foreach
```csharp
foreach (type variableName in arrayName) 
{
  // code block to be executed
}

// EXAMPLE
string[] cars = {"Volvo", "BMW", "Ford", "Mazda"};
foreach (string i in cars) 
{
  Console.WriteLine(i);
}
```

# OUT
- The `out` parameter must have the `out` keyword and its expected type
- The `out` parameter must be set to a value before the method ends

```csharp
static string Yell(string phrase, out bool wasYellCalled)
{
  wasYellCalled = true;
  return phrase.ToUpper();
}
```

# Alternate Expressions
## Expression bodied definitions
- Expression-bodied definitions are the first “shortcut” for writing methods.
```csharp
// METHOD
bool IsEven(int num)
{
  return num % 2 == 0;
}

// EXPRESSSION BODIED DEFINITION
bool isEven(int num) => num % 2 == 0;
```

## Methods as agruments
- How methods are passed to other methods as arguments.
- Say we need to check if there are even values in an array (you don’t need to know much about arrays here, except that they are lists of values).

```csharp
int[] numbers = {1, 3, 5, 6, 7, 8};
 
public static bool IsEven(int num)
{
  return num % 2 == 0;
}

bool hasEvenNumber = Array.Exists(numbers, IsEven);
```

## Lambda expressions
- lambda expressions, are great for situations when you need to pass a method as an argument.
- Generally lambda expressions with one expression take this form. They use the fat arrow, no curly braces, and no semicolon (`;`):

```csharp
// METHOD
int[] numbers = {1, 3, 5, 6, 7, 8};
 
public static bool IsEven(int num)
{
  return num % 2 == 0;
}
 
bool hasEvenNumber = Array.Exists(numbers, IsEven);

// LAMBDA EXPRESSION
bool hasEvenNumber = Array.Exists(numbers, (int num) => num % 2 == 0 );

// WITH MORE THEN ONE EXPRESSION
(input-parameters) => { statement; }

bool hasBigDozen = Array.Exists(numbers, (int num) => {
  bool isDozenMultiple = num % 12 == 0;
  bool greaterThan20 = num > 20;
  return isDozenMultiple && greaterThan20;
});
```

# Classes
- In C#, a custom data type is defined with a _class_, and each instance of this type is an _object_.
- A _class_ represents a custom data type. In C#, the class defines the kinds of information and methods included in a custom type.
- The code for a class is usually put into a file of its own, named with the name of the class. In this case it’s **Forest.cs**. This keeps our code organized and easy to debug.

```csharp
// CREATE A CLASS
class Forest {

}

// CALL A CLASS
// We could say f is an instance of the Forest class, or f is of type Forest.
Forest f = new Forest();
```

## Static classes
- A static class cannot be instantiated, so you only want to do this if you are making a utility or library, like `Math` or `Console`.

## Fields
- Fields are one type of class _member_, which is the general term for the building blocks of a class.
- Each field is a variable and it will have a different value for each object.
- In this case `string`s default to `null`, `int`s to `0`, and `bool`s to `false`. You can find the default values for more types in [Microsoft’s default values table](https://docs.microsoft.com/en-us/dotnet/csharp/language-reference/keywords/default-values-table).

```csharp
class Forest {
  public string name;
  public int trees;
}
```

- Once we create a `Forest` instance, we can access and edit each field with dot notation:

```csharp
Forest f = new Forest();
f.name = "Amazon";
Console.WriteLine(f.name); // Prints "Amazon"
 
Forest f2 = new Forest();
f2.name = "Congo";
Console.WriteLine(f2.name); // Prints "Congo"
```

## Properties
- Properties are another type of class member. Each property is like a spokesperson for a field: it controls the access (getting and setting) to that field. We can use this to validate values before they are set to a field. A property is made up of two methods:
	- a `get()` method, or getter: called when the property is accessed
	- a `set()` method, or setter: called when the property is assigned a value

```csharp
// BASIC PROPERTY WITHOUT VALIDATION
public int area;
public int Area
{
  get { return area; }
  set { area = value; }
}

// WITH VALIDATION
public int Area
{
  get { return area; }
  set 
  { 
    if (value < 0) { area = 0; }
    else { area = value; }
  }
}
```

- The `Area` property is associated with the `area` field. It’s common to name a property with the title-cased version of its field’s name, e.g. `age` and `Age`, `name` and `Name`.

### Example
#### Forest.cs
```csharp
using System;

namespace BasicClasses
{
  class Forest
  {
    public string name;
    public int trees;
    public int age;
    public string biome;

    public string Name
    {
      get { return name; }
      set { name = value; }
    }

    public int Trees
    {
      get { return trees; }
      set { trees = value; }
    }
    
    public string Biome
    {
      get { return biome; }
      set 
      {
        if (value == "Tropical" || value == "Temperate" || value == "Boreal")
        {
          biome = value;
        }
        else {
          biome = "Unknown";
        }
      }
    }
  }
}
```

#### Program.cs
```csharp
using System;

namespace BasicClasses
{
  class Program
  {
    static void Main(string[] args)
    {
      Forest f = new Forest();
      f.Name = "Congo";
      f.Trees = 0;
      f.age = 0;
      f.Biome = "Tropical";
      
      Console.WriteLine(f.Name);
    }
  }
}
```

## Automatic properties
- The basic getter and setter pattern is so common that there is a short-hand called an _automatic property_.
```csharp
// WITHOUT AUTOMATIC PROPERTIES
public string name;
public string Name
{
	get { return name; }
    set { name = value; }
}

// WITH AUTOMATIC PROPERTIES
public string Name
{ get; set; }
```

### Example
#### Forest.cs
```csharp
using System;

namespace BasicClasses
{
  class Forest
  {
    public int age;
    public string biome;
    
    public string Name
    { get; set; }
    
    public int Trees
    { get; set; }
    
    public string Biome
    {
      get { return biome; }
      set
      {
        if (value == "Tropical" ||
            value == "Temperate" ||
            value == "Boreal")
        {
          biome = value;
        }
        else
        {
          biome = "Unknown";
        }
      }
    }
  }
}
```

### Static fields and properties
- The definition of what a forest is applies to all `Forest` objects, not just one — there should only be one value for the whole class. This is a good use case for a static field/property.
- To make a static field and property, just add `static` after the access modifier (`public` or `private`).

```csharp
class Forest
{
  private static string definition;
  public static string Definition
  { 
    get { return definition; }
    set { definition = value; }
  }
}
```

- It is associated with the class not an instance. So its accessed using:

```csharp
static void Main(string[] args)
{
  Console.WriteLine(Forest.Definition);
}
```

## Public vs Private
- With public any code outside of the class can “sneak past” our properties by directly accessing the field.
- We can fix this by using the _access modifiers_ `public` and `private`:
	- `public` — a public member can be accessed by any class
	- `private` — a private member can only be accessed by code in the same class

## Get only properties
- Say we want programs to get the value of the property, but we don’t want programs to set the value of the property. Then we either:
	1.  don’t include a `set()` method, or
	2.  make the `set()` method private.

```csharp
// 1
public string Area
{
  get { return area; }
}

// 2
public int Area
{
  get { return area; }
  private set { area = value; }  
}
```

## Methods
- The third type of member in classes is _methods_.
- In the past you learned that methods are a useful way to organize chunks of code to perform a task. But most methods belong to a class (even the ones you have written!)

```csharp
class Forest {
  public int Area
  { /* property body omitted */  }
  public int IncreaseArea(int growth)
  {
    Area = Area + growth;
    return Area;
  }
}

// CALL THE METHOD
Forest f = new Forest();
int result = f.IncreaseArea(2);
Console.WriteLine(result); // Prints 2
```

### Static methods
- If the behavior isn't specific to any one instance - it applies to the class itself and it should be static.
- To make a static method, just add `static` after the access modifier (`public` or `private`).

```csharp
class Forest
{
  private static string definition;
  public static void Define()
  { 
    Console.WriteLine(definition); 
  }
}
// Notice that we added `static` to both the field `definition` and method `Define()`.
// This is because a static method can only access other static members. It cannot access instance members.
```

## Constructors
- It would be nice if we could write a method that’s run every time an object is created to set those values at once.
- C# has a special type of method, called a _constructor_, that does just that. It looks like a method, but there is no return type listed and the method name is the name of its enclosing class.
- If no constructor is defined in a class, one is automatically created for us. It takes no parameters, so it’s called a _parameterless constructor_.

```csharp
class Forest
{
  public int Area;
 
  public Forest(int area)
  {
    Area = area;
  }
}

// Constructor is called here
Forest f = new Forest(400);
```

### Overloading constructors
- Just like other methods, constructors can be overloaded. For example, we may want to define an additional constructor that takes one argument:

```csharp
public Forest(int area, string country)
{ 
  this.Area = area;
  this.Country = country;
 }
 
public Forest(int area)
{ 
  this.Area = area;
  this.Country = "Unknown";
}
```

### Static constructors
- An instance constructor is run before an instance is used, and a _static constructor_ is run once before a class is used.
- This constructor is run when either one of these events occurs:
	- Before an object is made from the type.
	- Before a static member is accessed.

```csharp
class Forest 
{
  static Forest()
  { /* ... */ }
}
```

Runs when the following is used in main()
```csharp
Forest f  = new Forest();
Forest.Define();
```

## Recap
- Creatin a custom data type in c#:
- Define a _class_
- Instantiate an _object_ using `new`
- Define _fields_, the pieces of data for each class
- Define _properties_, the spokespeople for each field
- Define _automatic properties_, the shorthand for making properties
- Define _methods_, the actions a class can take
- Define _constructors_, the special methods called when a class is instantiated
- Overload _constructors_ and reuse code with `this`
- Control access to class members using `public` and `private`

## Interfaces
- interfaces are sets of actions and values that describe how a class can be used.
- Every interface should have a name starting with “I”. This is a useful reminder to other developers and our future selves that this is an interface, not a class.
- An interface is a set of actions and values, but it doesn’t specify how they work. Notice that the property and method bodies are not defined.
- Just like classes, interfaces are best organized in their own files. 

```csharp
interface IAutomobile
{
  string Id { get; }
  void Vroom();
}
```

### Implementing an interface
- In C#, we must first clearly announce that a class implements an interface using the colon syntax:

```csharp
class Sedan : IAutomobile
{
  public string LicensePlate
  { get; }
 
  // and so on...
}
```

### Example
#### Sedan.cs
```csharp
using System;

namespace LearnInterfaces
{
  class Sedan : IAutomobile
  {
  	public string LicensePlate
    { get; }

    public double Speed
    { get; }

    public int Wheels
    { get; }
    
    public void Honk()
    {
      Console.WriteLine("HONK!");
    }
    
  }
}
```

#### IAutomobile.cs
```csharp
using System;

namespace LearnInterfaces
{
  interface IAutomobile
  {
    string LicensePlate { get; }
    double Speed { get; }
    int Wheels { get; }
    void Honk();
  }
}
```

# Inheritance
- With inheritance, you can define one superclass that contains the shared members

## Superclass and subclass
- In inheritance, one class inherits the members of another class. The class that inherits is called a _subclass_ or _derived class_. The other class is called a _superclass_ or _base class_.

```csharp
// UPPERCLASS
class Vehicle
{
}

// SUBCLASS
class Sedan : Vehicle
{
}
```

- A class can extend a superclass and implement an interface with the same syntax. Separate them with commas and make sure the superclass comes before any interfaces:

```csharp
class Sedan : Vehicle, IAutomobile
{
}
```

## Access inherited member with Protected
- Remember `public` and `private`? A `public` member can be accessed by any code outside of the enclosing class. A `private` member can only be accessed by code within the same class.
- Making the setter public is not secure. Making it private is too restrictive – we only want the subclass `Sedan` to access the property. C# has another access modifier to solved that: `protected`!
- A _protected_ member can be accessed by the current class and any class that inherits from it. In this case, if the setter for `Vehicle.Wheels` is protected, then any `Vehicle`, `Truck`, and `Sedan` instance can call it.

### Example
#### Vehicle.cs
```csharp
using System;

namespace LearnInheritance
{
  class Vehicle
  {
    public string LicensePlate
    { get; protected set; }

    public double Speed
    { get; protected set; }

    public int Wheels
    { get; protected set; }

    public void SpeedUp()
    {
      Speed += 5;
    }

    public void SlowDown()
    {
      Speed -= 5;
    }
    
    public void Honk()
    {
      Console.WriteLine("HONK!");
    }

  }
}
```

#### Sedan.cs
```csharp
using System;

namespace LearnInheritance
{
  class Sedan : Vehicle, IAutomobile
  {
    public Sedan(double speed)
    {
      Speed = speed;
      LicensePlate = Tools.GenerateLicensePlate();
      Wheels = 4;
    }
    
  }
}
```

### Access inherited members with base
- We can refer to a superclass inside a subclass with the `base` keyword.

```csharp
base.SpeedUp();
```

### Overwrite inherited members
- To _override_ an inherited method, use the `override` and `virtual` modifiers.
- In the superclass, we mark the method in question as `virtual`, which tells the computer “this member might be overridden in subclasses”:

```csharp
public virtual void SpeedUp()
```

- In the subclass, we mark the method as `override`, which tells the computer “I know this member is defined in the superclass, but I’d like to override it with this method”:

```csharp
public override void SpeedUp()
```

### Example
#### Bicycle.cs
```csharp
using System;

namespace LearnInheritance
{
  class Bicycle : Vehicle
  {
    public Bicycle(double speed) : base(speed)
    {
      Wheels = 2;
    }

    public override void SpeedUp()
    {
      Speed += 5;
      if (Speed >= 15)
      {
        Speed = 15;
      }
    }

    public override void SlowDown()
    {
      Speed -= 5;
      if (Speed <= 0)
      {
        Speed = 0;
      }
    }

  }
}
```

#### Vehicle.cs
```csharp
using System;

namespace LearnInheritance
{
  class Vehicle
  {
    public string LicensePlate
    { get; private set; }

    public double Speed
    { get; protected set; }

    public int Wheels
    { get; protected set; }

    public Vehicle(double speed)
    {
      Speed = speed;
      LicensePlate = Tools.GenerateLicensePlate();
    }

    public virtual void SpeedUp()
    {
      Speed += 5;
    }

    public virtual void SlowDown()
    {
      Speed -= 5;
    }
    
    public void Honk()
    {
      Console.WriteLine("HONK!");
    }

  }
}
```

