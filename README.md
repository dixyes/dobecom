# dobecom

 yet a linux command-line Dr.com client for CUST
 COPYLEFT(only parts by myself) !
### acknowledgement
 protocol detail refer to [drcom-generic](https://github.com/drcoms/drcom-generic) by latyas.
 
 md5 is using L. Peter Deutsch 's edition.
### doge
    :::::::::::::::::::::::::::::::::::::::::::::::::::::::~~=====+++++++??????????+=====+++++++++++++++
    ::::::~:::::::::~:~:::::::~::::::::::::::::::::::::::::~~====++++???++????????I?++++++++++++++++++++
    :::::::::::::::::~~~~~~::::::::::::::::::::::::::::::::~~~=====+II?+=====+++++?+++?+++++++++++++++++
    :::::::::::::::~~?I??++=~::::::::::::::::::::::::::::::~~~====+I7II?==~~~======+++???++++??+++++++++
    :::::::::::::::~?$$7II7?+~::::::::::::::::::::::::::::::~~====?77II+==~~~~=======++???++????+?+?++++
    :::::::::::::::=7$$$II7I?+~:~::::::::::::::::::::::::::::~===?7777I++=~~~~~=======+++++++???????++++
    ::::::::::::~:~I$$Z$$7I?II?+~::::::::::::::::::::::::::::~~=?I7777I++=~~~~~~~~==~~~=======++++?+????
    ::::::::::::::~$$$$77II?III?+=~::::::::::::::::::::::::::~~+I77777I++====~~~~~~~~~~~~~~~~=======++++
    ::::::::::::~~+$$$$77I7IIII7?++~~:::::::::::::::::::::::~~?I77777II??=====~~~~~=======~~~~~~~~~~~~==
    ::::::::::::::?$$$7$$7$77III$7I?+~~::::::::~::::::::~:~=+II7777$7II??+===++==============~~~~~~~~~~~
    :::::::::::::~I$777$$Z$$777I7$7II?=:::~:~~~~~~~~~=++????????????II77I+++??????++=+===========~~~~~~~
    :::::::::::::~7$77$$ZZZZ$$777$Z77I????????I???????????????????++???7I?+IIIIIIIII???I??+++++++====~~~
    :::::::::::::~7$$7$ZOOOOOO$777$O$7777$IIII????????????II??????+++++++???IIIIIII777777777III????+++++
    :::::::::::::~I$$77$ZO888Z$$777ZZ$777$I????++??????IIIIIIII????+++++++++?IIIIIIIIII7777777777IIIII??
    ::~~:::::::::~?7777$ZO888Z7I7777ZZZZ7I??I??+???????IIIIIIIII???++========++?IIIIIIIIIIII777777777777
    ::::::::::::::+77777$O8DNOZ77777ZZZI???I?I???I????I?IIII77III??+=+=========+++??IIIIIIIIIIII77777777
    ::::::::::::::~I77I77$88DDD$$77Z$I??I??????I??????IIIIII?I7II?++==~=~=+=+========+?IIIIIIIIIIII77777
    :::::::::::::::=77III7Z8D8DDZ7777???I??????I?I???I?I????II77I??+====~~=+++=========+??IIIIIIIII77777
    ::::::::::::::~+7$7I777$Z8DO8Z7?????I?????I???+??++++???III7II?+========+++=========+??IIIIIIIIIII77
    :::::::::::::~=+778877I77$Z7II??????????IIIII???+++=+++?IIIIIII?++====+====++========+?????IIIIIII77
    :::::::::~:~~~=?77III777777I?????+??????I?IIII?++=+++==++II7I7II?++=++?++??+==========++??????IIIIII
    :::::::::::~~=+I$$$$7777I??+?++++???????II?????++++++==++?IIIIII??++=?I8NNDD7+==~~===~====+++++????I
    :::::~::::~~=+?I$Z$$7777??+++++?????II??III?????++++++==+????I??+???+I8~8ZIZI?=~:::~=====~========++
    ::::::~::~~~=+?7$ZZZ7II?+++++?+++??????II??II?II7$?+++++++?+++?++++??IONDD8D=7~::,,::~=~~~~=~==~====
    ::::::::::~=+?I7$OZ77I??+++???+++++??????I7I7NNMM8NDII??????+++?++++++?NDOO8+7=~~:,,,:~==~~~~~~~~~~~
    ::::::::::~=+?I7$Z77I?????+?????++??+??I?I7ONNN8?8=?N8ZII?I?+++++++++=++7ZD$$I=~~::,,::~~~~~~~~~~~~~
    ::::::::::~=+?II777I?????????????++??+??I78NND8NDN$=7NDO$7I?+++====+++++==?I?+++=~:,,,:~=~~~~~~~~~~~
    ::::::::::~=+?III7III?????+?+?++++++++++?+?OODDNN88I7ND8$7I?++=++=====+++====++++~::::::~~~=~~~~~~~~
    :::::::::~~=??IIIII????+++++++++=+======+++=IZO88N$ZDDZII7??++==============~====~:::::::=~~~~~~~~~~
    ::::::::::~+?II?II????+++============~===++++++I777I?+++????+++=====+=+===+==~~~~::::::::~~~~===~~~~
    :::::::::~=+???I???+?+++======++===~~~~==+++??++?I????++????+++======++?++??I7I=::::::::::~~=======~
    :::::::::~=???????+++==+=======++=~~==~===++?+???+??++=++++++===+~+++=?$OZ$$7$$$77:,:~::::~~=======~
    ::::::::~+?+??????++++========~=~~~~~~~===+++++++++====++++++==~==~=+$O88DNNNNDNDD8,:::::~===+====+?
    :::::::~~++??+???++++==+=======~~~~~==============~~===+=+++===~~~~=788NNNMMNNDDMND~:,~:~::~+++=+?7Z
    ::::::~~=+?????I???++==+==========~~===========~~=~~~===+=======~=~=78DNNMMMNNDDN8I+:::~~::~=+++?7$$
    ::::~:~~=+?????III??+++++++================~=~~~~~=~======+===~~===+?ODMMNNDNDNDDD8?=~::~:::=++++???
    :::::~~=??+???IIII??+???+++++==+====~~~===~~=~==~========++++?++??++?$O8NNNDDDNDDD$?=~~===::=+++++==
    ::::~~~=+?????IIIII????++++++++++========~~===~+=========++++==+==++?I$OOODDDNNDDZ$I?+=~~~~~+++++++=
    ::::~~=++??I???I7I7II??++++++++?+=+==++=====+===========+++??+?I+I=++?I78888D8DOOO$I?==~~~:~=+++++++
    :::~~~=+???I?II77IIII??++==++++?++++++++=+++===++++=++++??+?+?+++?+I?I$ZOO8O8OOZOZZ??=~~~:~~=+++++++
    :::~~~=+????III?I7II????+++++=++++++++==++++++++++++++??+?????I?????7$$$OOZ88NDDDO$I+==~:~~~=+++++++
    ::::~=++??IIIII?IIII??+++=+======++++++===+++??+++++++III????I??II??7$Z88NNNNNNDOOZ+==~=~:~~=+++++++
    ~:~:~=++???IIIIIII?II?+++==========++++++=++++++++++??IZO8$O$7I++??7Z8NDNDD8D8DOOZ?=~=~~~:~~=++++++=
    ~~~~=++???II?IIIII7III??++++==+======++++++=++++++++??+77ZOODN8DDZDDD888888888OO7I+==~~~~~~~~~~:::::
    ::~~=+????IIIIIIIIIIII?+??++++=++++=+=++=++++=++?++++++??7Z7$$ZOZ8D8OZZOZOOOZZ$I+====~~~~~~:::::::::
    ::~~+???II77I777I7IIIIII????+++++++++++++++++++++++++++++?II777I77$$$III7$77$7I?+===~:~~~~::::::::::
    ::~=+?I??III7777IIII?IIII???++++++++==+++++?+?+?+++??++++++???II???I???I7II77?+++====~~~~~::::::::::
    ::~++??IIIII7777I7IIIIIIII?????++++====++++?+???++++???++?++++++++??????+++?++======~~~~~:::::::::::
    ::~=+?IIIIII77777I7III77III????+++++=====+=+++++???+???????????????++++++++=========~~~~~:::::::::::
    :~~++?IIIIII777$7777IIIIII??+???+++=+=+===+=+++++?????????????????I??++?++==++======~~==~:::::::::::
    :~=++?IIIIII7I77777777IIIII???++??+++++++======+=+?????????+???+++?++++++++++===========~::::::~:~~~
    ~~=++????IIIII7777777II7III??++??+++++++=++++====++???????????+???++++++++++=+=======+==~~:::::~~~~~
    :~=++++???II??II7777777II???I?????+++?++++++====+++???????+??+????+?++++++++=+===++==+==~~~~~~~~~~~~
    ~~==++++++??????777II7II????++++?+++?+???+++++++=++I???????????????+++++++++++=+++++====~~~~~~~~~~~~
    ~~~==+++++?+?I???II77IIIIII????+++++++++????+?+?+??????????I?????+??+++++++++++++++=====~~~~~~~~~~~~
    ~~~==++++++++++????I?I??????+?+++???+++???????????????????????++??+++?++++++??++++=======~~~~~~~~~~~
