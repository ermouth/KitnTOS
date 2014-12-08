Kit’n’TOS. Project for Koding hackthon 2014
=======
[![Koding Hackathon](https://github.com/koding/hackathon.submit/raw/master/images/badge.png?raw=true "Koding Hackathon")](https://koding.com/Hackathon)

[This is a preview version of Kit’n’TOS](http://carpogoryanin.koding.io/#/) 
– public service for TOSes and other TL;DRs. Main feature – every 
section of every doc can be ‘kittenized’ by end users. More kittens – more friendly doc.

###Description

Kit‘n‘TOS is pure javascript project. User puts URL of external HTML page with TL;DR, server fetches the page,
parses it, flattens, and then allows each section to be rated. Rating is kitten-based: for nice texts – nifty kittens, 
for awkward ones – angry kittens. There are 5 grades. Also user can comment his decision – 50 chars more.

Comments and kittens are shown aside text – so looking into kitns‘ faces it’s easy to estimate how
friendly doc is.

The main challenge was to create parser, that flattens sometimes very spriggy and strange 
DOM structure of TL;DRs. Parser was created using browser IDE of [cloudwall.me](http://cloudwall.me) and ported to node.js. 
It uses mostly jQuery – so porting per se took very little time.

We use two DBs – Mongo to keep sessions (users can log in using Twi, Github or FB) and CouchDB to persist fetched 
docs and votes. 

[jQuery.my](http://jquerymy.com) plugin is used to render and manage UI.

### Screenshots
Homepage, first sketch.
[![Koding](http://jquerymy.com/kod/kod1.png "KitnTOS first sketch")](http://jquerymy.com/kod/kod1.png)

IDE, fragment of parser testbench.
[![Koding](http://jquerymy.com/kod/kod2.png "Clouwall.me IDE")](http://jquerymy.com/kod/kod2.png)

Koding IDE.
[![Koding](http://jquerymy.com/kod/kod3.png "Koding IDE")](http://jquerymy.com/kod/kod3.png)


###APIs and libs

We used:
 * [Koding.com](http://koding.com) environment to run project
 * [Hackathon Starter](https://github.com/sahat/hackathon-starter) – cozy environment for node.js apps
 * [cloudwall.me](http://cloudwall.me) IDE to develop UI
 * [node.js](http://node.js) – for everything
 * [Sugar](http://sugarjs.com) to make JS even more sweet
 * [CouchDB](http://couchdb.apache.org) – for docs and nice indexed map-reduce
 * [jQuery.my](http://jquerymy.com) plugin to render UI
 * [jQuery](https://www.npmjs.org/package/jquery/) to manipulate DOM
 
