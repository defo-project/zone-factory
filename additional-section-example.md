```
>>> import dns.resolver
>>> myreso = dns.resolver.make_resolver_at('::1')
>>> ans = myreso.resolve('alias.esni.defo.ie','HTTPS')
>>> for rr in ans:
...     print(rr)
... 
0 cover.defo.ie.
>>> resp = ans.response
>>> print(resp.answer)
[<DNS alias.esni.defo.ie. IN HTTPS RRset: [<0 cover.defo.ie.>]>]
>>> print(resp.additional)
[<DNS cover.defo.ie. IN AAAA RRset: [<2a00:c6c0:0:116:5::10>]>, <DNS cover.defo.ie. IN A RRset: [<213.108.108.101>]>, <DNS cover.defo.ie. IN HTTPS RRset: [<1 . ipv4hint="213.108.108.101" ech="AID+DQA8QwAgACDb/AIvmhfurmhHAS546acDK4cBQYx/Slfo10fod06lRgAEAAEA...>]>]
>>> 
```
