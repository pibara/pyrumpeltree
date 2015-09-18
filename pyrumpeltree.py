"""Python3 port of RumpelTree++.

This module constitutes a non capability-compatible port of RumpelTree++ to Python 3. 
The pyrumpeltree module is meant as the core hashing and encoding logic for servers 
and/or file-systems implementing sparse-cap designated singly attenuated Rumpelstiltskin DAG's.

For more information on sparse-cap designated singly attenuated Rumpelstiltskin DAG's, and the way 
that pyrumpeltree implements these:

  https://minorfs.wordpress.com/2014/02/20/rumpelstiltskin-and-his-children/
  https://minorfs.wordpress.com/2014/03/21/rumpelstiltskin-and-his-children-part-2/

While the API talks of servers and clients, please take note that there isn't actually any server or
client implemented in this module. The server refers to the logic that is expected to reside inside
of 'your' server of file-system logic. And chances are you won't ever need to use the 'client' part.
The 'client' par of the API is meant for scalability of your system. While some server side operations
require use of a server side secret, some operations don't and may be offloaded to the client side of
things. The client there could be a real network client or a process using your user-space file-system.
It is possible to choose to only allow some clients to do client side operations by means of a cloud 
secret that is shared between the server and the clients.

After creating a server object using the create_server function, this server object may be used to
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
 * The ecryptuin_key is meant to be used as a node specific File Encryption Key for encrypting
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
the usage of this python library, please contact the author : pibara[at]gmail[dot]com. 

"""

import base64
import hmac
import hashlib
import os

def _macfun(data,key):
  return hmac.new(key, msg=data, digestmod=hashlib.sha256).digest()

#This little helper class does the actual RumpleTree hashing, capabilities and storage info stuff.
class _Engine:
  def __init__(self,secret,cloudsecret):
    self.secret=secret            #Secret that should NOT be shared with client instances.
    self.cloudsecret=cloudsecret  #Secret that should be shared with client instances to allow client side attenuation.
  def nodecaps(self,firstcap):
    if firstcap[1] == 'o': #Check for read-only or attenuated cap prefix.
      cap1=None            #There is no unattenuated/rw cap for this one
      cap2=firstcap        #We use the function argument as ro/attenuated cap
      key2=base64.b32decode(firstcap[3:]+"====") #Calculate the FEK by decoding the non-prefix part of the ro/attenuated cap.
    else:
      cap1=firstcap        #Use the function parameter as rw/unattenuated cap
      key1=base64.b32decode(firstcap[3:]+"====") #Decode the non-prefix part of the unattenuated cap.
      key2=_macfun(b"read-only::nosalt",key1) #Derive the FEK by hashing a fixed string with cap1 as key.
      cap2="ro-" + base64.b32encode(key2)[:-4].decode("utf-8") #Also encode the FEK into a cap for ro/attenuated access.
    key3=_macfun(self.cloudsecret.encode(),cap2.encode()) #Derive a third key from the attenuated/ro cap
    str3= base64.b32encode(key3)[:-4].decode("utf-8") #Now start off with encoding in base32.
    location = str3[0:3] + "/" + str3[3:6] + "/" + str3[6:] #Create a path for a ballanced directory tree for where to serialize our nodes.
    return (cap1,cap2,location,key2) 
  def derive(self,parentstoragekey,key,attenuated):
    #Derive an unattenuated child cap using attenuated parent cap
    intermediatekey =  _macfun(self.secret,parentstoragekey)
    childkey = _macfun(key.encode(),parentstoragekey)
    if attenuated == False:
      return "rw-" + base64.b32encode(childkey)[:-4].decode("utf-8")
    else:
      #Attenuate the result if requested.
      key2=_macfun(b"read-only::nosalt",childkey)
      return "ro-" + base64.b32encode(key2)[:-4].decode("utf-8")
    

class Storage:
  """Trivial class combining the two storage entity attributes"""
  def __init__(self,location,key):
    self.location=location
    self.key=key
  def __call__(self):
    """Returns storage entity location attribute"""
    return self.location
  def crypto_key(self):
    """Returns storage entity FEK attribute"""
    return self.key

class Node:
  """Represents a single node in the Rumpelstiltskin singly attenuated DAG."""
  def __init__(self,engine,firstcap):
    self.engine=engine
    if firstcap[1] == "w":
      self.ro=False
    else:
      self.ro=True
    (self.rwcap,self.rocap,self.location,self.storagekey)=self.engine.nodecaps(firstcap)
  def __getitem__(self,key):
    """Get a Node object for a named entity one level down in the tree.""" 
    if self.ro:
        return Node(self.engine,self.engine.derive(self.storagekey,key,True))
    else:
        return Node(self.engine,self.engine.derive(self.storagekey,key,False))
  def __eq__(self,other):
    return self.rocap == other.rocap
  def cap(self):
    """Get the least attenuated sparse capability available for this Node""" 
    if self.rwcap == None:
      return self.rocap
    else:
      return self.rwcap
  def attenuated(self):
    """Get the read-only or attenuated access sparse capability for this node"""
    return Node(self.engine,self.rocap)
  def isattenuated(self):
    """Returns a boolean indicating if access to this Node is attenuated or read only"""
    return self.ro
  def storage(self):
    """Returns a Storage entity for this Node"""
    return Storage(self.location,self.storagekey)

class Server:
  """Helper class for accessing root Node's within a Rumpelstiltskin singly attenuated DAG 
     on the server or file-system side of things."""
  def __init__(self,secret,cloudsecret):
    self.engine=_Engine(secret,cloudsecret)
  def __getitem__(self,rootcap):
    """Get any Node by one of its sparse caps."""
    return Node(self.engine,rootcap)

class Client:
  """Helper class for doing some non-decomposition operations on Nodes at the client or 
     user-process side of things."""
  def __init__(self,cloudsecret):
    self.pseudoserver=Server("",cloudsecret)
  def __getitem__(self,key):
    """Get any Node by one of its sparse caps."""
    return self.pseudoserver[key]
  def attenuate(self,cap):
    """Get the attenuated/read-only sister sparse cap belonging with an unattenuated or 
       read/write sparse cap"""
    return self.pseudoserver[key].attenuated()
  def storage(self,cap):
    """Get the Storage entity belonging to the node designated by the sparse cap provided."""
    return self.pseudoserver[cap].storage()

def randomsecret():
  """Helper function for generating a decent size secret. 

     This secret should be stored persistently with strict access rights allowing only the server 
     or file-system process access to the persistently stored secret."""
  secret=""
  for iteration in range (0,256):
    secret += base64.b32encode(os.urandom(32))[:-4].decode("utf-8")
  return secret.encode()
  
def randomrootcap():
  """Generate a random rootcap (and thus a new Rumpelstiltskin singly attenuated DAG)."""
  return "rw-" + base64.b32encode(os.urandom(32))[:-4].decode("utf-8")

def pass2rootcap(passwd):
  """Create a rootcap for a new Rumpelstiltskin singly attenuated DAG using a password"""
  binkey=hashlib.pbkdf2_hmac('sha256', passwd.encode(), b'Rumpelstiltskin', 131072)
  return "rw-" + base64.b32encode(binkey)[:-4].decode("utf-8")

def create_server(secret,cloudsecret=""):
  """Create a server side or file-system side 'server' object for looking up and processing 
     Rumpelstiltskin singly attenuated DAG nodes.""" 
  return Server(secret,cloudsecret)

def create_client(cloudsecret=""):
  """Create a (network or file-system) client side 'client' object for potentially doing some 
     client side operations in order to offload the server/file-system side with operations 
     that are possible on the client side."""
  return Client(cloudsecret)



if __name__ == "__main__":
  secret=randomsecret()
  cloudsecret=""
  server=create_server(secret,cloudsecret)
  rootcap=pass2rootcap("knockknockwhoisthere")
  topnode = server[rootcap] 
  attenuated=topnode.attenuated()
  derived=topnode["Bob"]
  da = derived.attenuated()
  ad = attenuated["Bob"]
  print(ad.cap()==da.cap(), ad.cap(),da.cap())
