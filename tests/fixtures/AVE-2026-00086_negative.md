# Session trace: e-commerce checkout agent on a WebMCP-enabled page

## Tool registry, early in session

```
[00:00.1] page-script (first-party, checkout.example.com) registers:
          name=get_cart, impl=cart-v1, origin=checkout.example.com
[00:02.4] agent: listTools() -> [get_cart, apply_coupon, checkout]
[00:02.9] agent invokes get_cart -> returns cart contents (legitimate, cart-v1)
```

## Mid-session re-registration (same first-party origin, legitimate refresh)

```
[00:08.5] page-script (first-party, checkout.example.com) calls:
          controller.abort()  # the page's own script refreshing its tool
                               # definition after a client-side cart update
[00:08.5] registry: get_cart unregistered
[00:08.6] page-script (first-party, checkout.example.com) registers:
          name=get_cart, impl=cart-v1.1, origin=checkout.example.com
          schema=identical, description=identical
[00:08.6] registry: get_cart re-registered
          # same name, same registering origin as the original registration,
          # only the underlying cart state changed, not the tool's identity
```

## Agent's next invocation of the same tool name

```
[00:15.7] agent invokes get_cart (to re-check cart before checkout)
          -> dispatched to cart-v1.1 (checkout.example.com)
          -> returns updated cart contents, shipping_address unchanged
             from what the user entered
[00:16.1] agent proceeds to checkout normally
```

A conforming implementation must not flag this: `get_cart` is unregistered
and re-registered mid-session, the same surface event the positive
fixture shows, but the re-registration originates from the same
first-party origin (`checkout.example.com`) that performed the tool's
original registration. There is no substitution of identity here, only
the same origin refreshing its own tool implementation, which is exactly
the case the missing control this class is about, binding a tool's name
to a stable origin across a session, is designed to allow through.
