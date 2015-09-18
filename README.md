# pyrumpeltree
This repository contains a Python(3) port of the C++ RumpelTree++ library:
  
  * https://github.com/pibara/Rumpeltreepp

It also contains a simple script and a few handfulls of symlinks that together demonstrate
the usage in a crude but hopefully educational way. You are invited to play with these scripts
on your \*NIX or Linux system to get a feel for the functionality of the library.

# Python3 port of RumpelTree++.
This module constitutes a non capability-compatible port of RumpelTree++ to Python 3. 
The pyrumpeltree module is meant as the core hashing and encoding logic for servers 
and/or file-systems implementing sparse-cap designated singly attenuated Rumpelstiltskin DAG's.
For more information on sparse-cap designated singly attenuated Rumpelstiltskin DAG's, and the way 
that pyrumpeltree implements these:

 * https://minorfs.wordpress.com/2014/02/20/rumpelstiltskin-and-his-children/
 * https://minorfs.wordpress.com/2014/03/21/rumpelstiltskin-and-his-children-part-2/

While the API talks of servers and clients, please take note that there isn't actually any server or
client implemented in this module. The server refers to the logic that is expected to reside inside
of 'your' server of file-system logic. And chances are you won't ever need to use the 'client' part.
The 'client' par of the API is meant for scalability of your system. While some server side operations
require use of a server side secret, some operations don't and may be offloaded to the client side of
things. The client there could be a real network client or a process using your user-space file-system.
It is possible to choose to only allow some clients to do client side operations by means of a cloud 
secret that is shared between the server and the clients.
After creating a server object using the create\_server function, this server object may be used to
convert sparse capabilities into Node objects. Basically any well formed sparse-cap is considered valid
by the library. The true validity should be bound to the existence of what the Node object designates.
That is, an invalid sparse capability will be a capability to a valid node that points into nothingness.

Conceptually a node consists of three properties:

 * A designating sparse capability indicating full unatenuated access to the node and all its children.
 * A designating sparse capability indicating attenuated access to the node and all its children.
 * A storage designation

The storage designation is meant to be used in the following way:

 * The storage relative path is meant to be used as obfuscated location indicator in a file-system 
   or database, indicating where the serialisation of the designated node is stored. 
   Note that this storing of serialized node's is not part of the functionality of pyrumpeltree.
 * The ecryptuin\_key is meant to be used as a node specific File Encryption Key for encrypting
   and decrypting the above mentioned serialisation.

The Node contains the abstraction of attenuation. Invoking 'attenuate' on a Node will return a copy of
that same Node that is missing its full unattenuated access capability. We refer to these nodes as
attenuated nodes. 
Next to attenuation, a Node also allows for decomposition. Using the index operator, a child node
can be derived using the childs name as local designation. this means that the child has a weak name 
that only designates within the context of its parent, and one or two strong names (sparse capabilities) 
that designate without such context. There is no '..' operation to get from a child to its parent just 
as there is no path from the attenuated access sparse cap to the unattenuated sparse cap. Enforcing
the directional property of decomposition and attenuation is the main feature of this library.
One important note to potential users: Depending on your threath model, you may want to consider using 
the original C++ implementation instead. You will be having powerfull sparse capabilities in process 
memory when using this library and high level languages like Python lack the ability to promptly wipe
sensitive memory after usage. This means that in Python the capabilities may linger in memory long after 
usage and a process memory dump may reveal these capabilities for a much longer timespan than they would 
when using the C++ library. On the other hand, low level languages come with their own issues conversely
related to the very same language features that allow promptly wiping sensitive data after usage. You 
should carefully consider your threath model before choosing for pyrumpeltree or opting for Rumpletree++
instead. 
If you find any bugs, see any cryptographical design problems in the algoritm or just want to discuss 
the usage of this python library, or have any ideas about improvements, please contact the author : 

pibara[at]gmail[dot]com.

Python 3 isn't really my normal language of choice so any tips on cleaning up my code or making it more pytonic
are very much welcomed. 

# The example tool

The tool rumpelbox is a simple busybox style all in one script that is symlinked multiple times to provide 
a set of tools to play around with the pyrumpeltree library functionality. The tool will store and consult 
encrypted files in the ~/.rumpeltree/ directory. When playing around with the tools you should try to keep 
track of fow new encrypted files get created there. Basically the tool uses the Rumpeltree logic and generated 
paths/crypto keys to store individually AES encrypted json serialized data or directory nodes in a 3 layer deep balanced
directory tree. Please remember this tool is meant to be educational only. Error handling is non existent and
there definetely are unacceptable race conditions making the tool unsuitable for any other purposes, but playing with
this tool seems to currently be the only way for quite some people to get a grasp of how the Rumpelstiltskin singly 
attenuated DAG tree algoritm does its thing, so please excuse the poor coding of rompelbox and go play with it for
a short while before looking at using the library in your own projects. That's what the rool is for and I can assure
you that if you have played with the tool for ten minutes and have observer the ~/.rumpeltree/ directory, you WILL have
a decent grasp of the potential of using either this Python port or the original C++ implementation  RumpelTree++.

 * rumpeldump  <cap>  : dump the decrypted node json data/
 * rumpells  <cap> : list the entities in a directory node and their respective sparse caps.
 * rumpelmkdir <cap> <childname> : Create a new directory node as child of an existing directory node.
 * rumpelnew  <password> : Create a new root node from a password generated root cap.
 * rumpelold  <password> : Get a reference to an existing root node using the pasword used in its creation.
 * rumpelrestore  <cap> : Dump the content of a data node to standard out.
 * rumpelrm  <cap> <name> : Delete a data node
 * rumpelrmdir <cap> <name> : Delete an empty directory node. 
 * rumpelro  <cap> : Get an attenuated (read only) cap for the given node,
 * rumpelsave <cap> <name>: Create a new data node and fill it with the content supplied through stdin.

 
