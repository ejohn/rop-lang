

This project is inspired by the paper [Return-Oriented Programming: Systems, Languages, and Applications](http://cseweb.ucsd.edu/~hovav/dist/rop.pdf) (Hovav Shacham et al.)

The idea is to build a turing complete catalog of ROP gadgets and provide a high level language to interact with them. My goal from the beginning of this project was to be able to write a simple sort program using this language.

All the demo scripts are in the demos folder.

In order to run the scripts turn off ASLR so that the program can autodetect the libc base address. It will also attempt to detect the address of BSS in order to create a custom stack in that location. If you wish to supply both the address of libc in memory and memory location to use for stack pivoting, you can do so by specifying it in the ROP script. See the file shell2.rop in demos for an example.

Compile the vulnerable program in vuln.c against the supplied libc library (Preferably inside a VM!)
```
echo 0 | sudo tee /proc/sys/kernel/randomize_va_space # Turn off ASLR
gcc -Xlinker -rpath=./ -m32 vuln.c -o vuln # Note: gcc-multilib needed

Optionally iistall the distorm library if you want to search for the gadgets in libc.
	cd distorm-1.7.30/
	sudo python setup.py install

Run scripts:
	python interpreter.py demos/sort.rop > payload # payload here is the binary data fed into a vulnerable program
	./vuln payload # vuln just loads the payload and executes it
```

One important thing to note is that the gadgets collection process is a hit or miss at this point of time. Some of the gadgets mentioned in the paper were missing in the version of libc I was using and I replaced them with equivalent gadgets, which is a tedious manual process. It is also likely you will not find equivalent gadgets in which case some changes might be needed to the corresponding higher level functions in runner.py. One of the future goals for this project is to make it more modular in order to reduce the changes that would be needed.


Credits:
This project made extensive use of [ROPEME](http://www.vnsecurity.net/2010/08/ropeme-rop-exploit-made-easy/) for finding gadgets.
