 A new mount namespace is created using either `clone(2)` or
       `unshare(2)` with the CLONE_NEWNS flag.  When a new mount namespace
       is created, its mount list is initialized as follows:
- If the namespace is created using clone(2), the mount list of
          the child's namespace is a copy of the mount list in the
          parent process's mount namespace.

- If the namespace is created using unshare(2), the mount list
          of the new namespace is a copy of the mount list in the
          caller's previous mount namespace.


[mount_namespaces](https://man7.org/linux/man-pages/man7/mount_namespaces.7.html)     

[mount-namespaces](https://www.redhat.com/en/blog/mount-namespaces)

[configuring-a-custom-domain-for-your-github-pages-site/verifying-your-custom-domain-for-github-pages](https://docs.github.com/en/pages/configuring-a-custom-domain-for-your-github-pages-site/verifying-your-custom-domain-for-github-pages)


