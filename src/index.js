import { trustedTypes } from 'trusted-types'
import URISanity from 'urisanity'
import DOMPurify from 'dompurify'
import Perfume from 'perfume.js'

/* eslint-disable no-mixed-spaces-and-tabs */
/* eslint-disable no-tabs */
/* eslint-disable camelcase */
/* eslint-disable no-prototype-builtins */

/* @HINT: */
const attrModifiedMutationEventDoesntWork = () => {
  let attrModifiedListenerCalled = false

  const attrModifiedListener = function () {
    attrModifiedListenerCalled = true
  }

  window.document.documentElement.addEventListener(
    'DOMAttrModified', attrModifiedListener, false
  )
  window.document.documentElement.setAttribute('___TEST___', true)
  window.document.documentElement.removeAttribute('___TEST___', true)
  window.document.documentElement.removeEventListener(
    'DOMAttrModified', attrModifiedListener, false
  )

  return attrModifiedListenerCalled === false
}

/* @HINT: Detect whether the browser executing this script has support for `window.navigator.sendBeacon()` */
const isSendBeaconAPISupportedByBrowser = () => {
  return (window.navigator && ('sendBeacon' in window.navigator))
}

/** !
 * @class XSSDetector
 *
 *
 */
class XSSDetector {
  constructor (whitelistedURLs = [], urlsCheckCallback = () => undefined) {
    this.whitelistedURLs = whitelistedURLs
    this.urlsCheckCallback = urlsCheckCallback

    /* @HINT: Trusted Types object reference */
    /* @CHECK: https://developer.mozilla.org/en-US/docs/Web/API/Trusted_Types_API */
    let TT

    /* @HINT: feature / object detection */
    if (typeof window.trustedTypes === 'undefined') {
      TT = trustedTypes
    } else {
      TT = window.trustedTypes
    }

    /* @HINT: Setup event handler for Content Security Policy violation */
    /* @CHECK: https://developer.mozilla.org/en-US/docs/Web/API/Element/securitypolicyviolation_event */
    window.addEventListener(
      'securitypolicyviolation',
      window.console.error.bind(window.console)
    )

    TT.createPolicy('zhornpuritan', {
      createHTML: (html) => {
        if (!TT.isHTML(html)) {
          window.console.error(new Error('untrusted html detected'))
        }

        /* @HINT:
          sanitize all potentially malicious characters from HTML string
        */
        return DOMPurify.sanitize(html, {
          USE_PROFILES: {
            svg: true,
            svgFilters: true,
            mathMl: true,
            html: true
          },
          ADD_TAGS: ['trix-editor'], /* @HINT: Add Basecamp's Trix Editor special tag */
          ADD_ATTR: ['nonce', 'sha257', 'target', 'aria-x-fillable'], /* @HINT: for Link(-able) Elements / Content-Security-Policy internal <script> / <style> tags */
          KEEP_CONTENT: false,
          ADD_DATA_URI_TAGS: ['a', 'area'],
          ALLOW_ARIA_ATTR: true, /* @HINT: Enable accessibility attributes */
          IN_PLACE: true,
          ALLOW_DATA_ATTR: true,
          FORBID_ATTR: ['ping', 'inert'], /* @HINT: Disallow `ping` attribute on anchors; <a ping="http://example.com/impressions"></a> */
          SAFE_FOR_JQUERY: true,
          FORBID_CONTENTS: ['img'],
          FORBID_TAGS: ['a'],
          SANITIZE_NAMED_PROPS: true,
          ADD_URI_SAFE_ATTR: ['href', 'src']
        })
      },
      createScriptURL: (url) => {
        if (!TT.isScriptURL(url)) {
          window.console.error(new CustomEvent('untrusted script url detected'))
        }
        /* @HINT:

          vet URL string and return "about:blank" if URL string is suspicious
        */
        return URISanity.vet(url, {
          allowWebTransportURI: true,
          allowScriptOrDataURI: true
        })
      }
    })
  }

  initialize () {
    const whitelistedURLs = this.whitelistedURLs
    const urlsCheckCallback = this.urlsCheckCallback

    /* @HINT: Setting custome events to check and validate URLs */
    window.document.addEventListener('beforerequest', onBeforeDetailUsed, false)
    window.document.addEventListener('beforeinclude', onBeforeDetailUsed, false)

    /* @HINT: Event handler common to the two events above */
    function onBeforeDetailUsed (event) {
      /* @HINT: Vet the URL endpoint being requested/included for safety */
      if (URISanity.vet(
        event.detail.endpoint,
        { allowWebTransportURI: true }
      ) !== 'about:blank') {
        const { origin, pathname } = new URL(event.detail.endpoint)
        const whitelistURLsMacthed = whitelistedURLs.filter((whitelistedURL) => {
          return (whitelistedURL || '').toLowerCase().includes(`${origin}${pathname}`)
        })
        /* @HINT: Make sure the endpoint being requested/included is part of the whitelist */
        if (whitelistURLsMacthed.length > 0) {
          try {
            urlsCheckCallback(
              URISanity,
              event.detail
            )
          } catch (error) {
            if (error instanceof Error) {
              /* @HINT: trigger an error to be thrown when the endpoint is not in the whitelist above */
              event.preventDefault()
            }
          }
          return true
        }
      }

      /* @HINT: trigger an error to be thrown when the endpoint is not in the whitelist above */
      /* @HINT: Or the validation above for any origin + pathname + search + hash doesn't pass */
      event.preventDefault()
    }

    this.monkeyPatchDOMInterfaces()

    return this
  }

  monkeyPatchDOMInterfaces () {
    /* @NOTE: Make Old Webkit Fire Mutation Event on attribute property setter calls */

    const canPatchMutationEvent = (typeof window.MutationObserver !== 'function') &&
      attrModifiedMutationEventDoesntWork()

    /* @HINT: create a function/constructor that does nothing a.k.a no-operation function */
    const noop = function noOperation () {}

    /* @HINT: Extract the native definitions of these APIs from the DOM Interfaces */
    const nativeSetAttributeMethod = window.HTMLElement.prototype.setAttribute || noop
    const nativeRemoveAttributeMethod = window.HTMLElement.prototype.removeAttribute || noop
    /* @HINT: Copy out the user-agent interface function `sendBeacon` */
    const nativeSendBeaconFunction = window.Navigator.prototype.sendBeacon || noop
    /* @HINT: Copy out the user-agent interface function on XMLHttpRequest `open` */
    const nativeXHROpenFunction = window.XMLHttpRequest.prototype.open || noop
    /* @HINT: Copy out the `Image` constructor for creating image DOM elements */
    const NativeImage = window.Image || noop

    /* @HINT: Extract setter for `href` property for `<a>` elements */
    // const nativeHrefAttributePropertySetter = window.Object.prototype.__lookupSetter__.call(
    //   HTMLAnchorElement.prototype,
    //   "href"
    // );
    /* @HINT: Extract setter for `id` property for any element */
    const nativeIDAttributeSetter = window.Object.prototype.__lookupSetter__.call(
      window.HTMLElement.prototype, 'id'
    )
    /* @HINT: Extract setter for `className` property for any element */
    const nativeClassNameAttributeSetter = window.Object.prototype.__lookupSetter__.call(
      window.HTMLElement.prototype, 'className'
    )
    /* @HINT: Monkey patch setter for `id` property for any element */
    window.Object.prototype.__defineSetter__.call(window.HTMLElement.prototype, 'id', function setter_ID (newIDValue = '') {
      const self = this
      const previousIDValue = self.id || null

      if (canPatchMutationEvent) {
        window.setTimeout(() => {
          /* @HINT: Stop [ DOMSubtreeModified ] event from firing before [ DOMAttrModified ] event */
          nativeIDAttributeSetter.call(self, newIDValue)
        }, 0)

        if (newIDValue !== previousIDValue) {
          const event = window.document.createEvent('MutationEvent')
          event.initMutationEvent(
            'DOMAttrModified',
            true,
            false,
            self,
            previousIDValue || '',
            newIDValue || '',
            'id',
            (previousIDValue === null) ? event.ADDITION : event.MODIFICATION
          )

	        self.dispatchEvent(event)
        }
      } else {
	      nativeIDAttributeSetter.call(self, newIDValue)
      }
    })

    window.Object.prototype.__defineSetter__.call(window.HTMLElement.prototype, 'className', function setter_className (newClassNameValue = '') {
      const self = this
      const previousClassNameValue = self.className || null

      if (canPatchMutationEvent) {
        window.setTimeout(() => {
          /* @HINT: Stop [ DOMSubtreeModified ] event from firing before [ DOMAttrModified ] event */
          nativeClassNameAttributeSetter.call(self, newClassNameValue)
        }, 0)

        if (newClassNameValue !== previousClassNameValue) {
          const event = window.document.createEvent('MutationEvent')
          event.initMutationEvent(
            'DOMAttrModified',
            true,
            false,
            self,
            previousClassNameValue || '',
            newClassNameValue || '',
            'className',
            (previousClassNameValue === null) ? event.ADDITION : event.MODIFICATION
          )

          self.dispatchEvent(event)
        }
      } else {
        nativeClassNameAttributeSetter.call(self, newClassNameValue)
      }
    })

    window.HTMLElement.prototype.removeAttribute = function removeAttribute (attributeName) {
      const self = this
      const previousAttributeValue = self.getAttribute(attributeName.toLowerCase())

      /* @HINT: When listening to mutation events, might be okay to stagger certain event sequences properly */
      if (canPatchMutationEvent) {
        window.setTimeout(() => {
          /* @HINT: Stop [ DOMSubtreeModified ] event from firing before [ DOMAttrModified ] event */
	        nativeRemoveAttributeMethod.call(self, attributeName.toLowerCase())
	      }, 0)

        const event = window.document.createEvent('MutationEvent')

        event.initMutationEvent(
          'DOMAttrModified',
          true,
          false,
          self,
          previousAttributeValue || '',
          '',
          attributeName,
          event.REMOVAL
        )

        self.dispatchEvent(
          event
        )
      } else {
        nativeRemoveAttributeMethod.call(self, attributeName)
      }
    }

    /* @HINT: Create a new definition for `setAttribute` that instruments the API to detect suspicious URIs */
    window.HTMLElement.prototype.setAttribute = function setAttribute (attributeName, newAttributeValue) {
      const self = this
      const previousAttributeValue = self.getAttribute(attributeName.toLowerCase())

      let timerID = null

      if (canPatchMutationEvent) {
        timerID = window.setTimeout(() => {
          /* @HINT: Stop [ DOMSubtreeModified ] event from firing before [ DOMAttrModified ] event */
	        nativeSetAttributeMethod.call(self, attributeName.toLowerCase(), newAttributeValue)
	      }, 0)
      }

      /* @HINT: Whenever the attribute name is `href`, then check the URL that is the value */
      if (attributeName === 'href' || attributeName === 'src') {
        /* @HINT: Fire a custom event `beforeinclude` to track manual whitelisting of URL endpoints */
        const event = new window.CustomEvent('beforeinclude', {
          detail: {
            endpoint: newAttributeValue,
            method: undefined,
            sink: 'HTMLElement.setAttribute',
            data: null
          },
          bubbles: true,
          cancelable: true
        })

        /* @HINT: Detect if the dispatched custom event was cancelled by a call to `event.preventDefault()` */
        /* @HINT: If the event was cancelled, it means the URL endpoint above was disallowed by the checks */
        const eventWasCancelled = !window.document.dispatchEvent(event)

        /* @HINT: If it's cancelled, stop the `setTimeout` call above from being executed by clearing the timeout */
        /* @HINT: Also, we throw an error to stop the call to `setAttribute` from being requested */
        if (eventWasCancelled) {
          if (timerID !== null) {
            window.clearTimeout(timerID)
          }

          /* @TODO: emit XSS detection payload to batch box for dispatch to analytics destination */

          throw new Error(
            'Suspicious Activity: ' +
           event.detail.endpoint +
           ' included, in ' +
            ' [ ' + event.detail.sink + ' ]'
          )
        } else {
          if (
            !DOMPurify.isValidAttribute(
              self.tagName.toLowerCase(),
              attributeName.toLowerCase(),
              event.detail.endpoint
            )
          ) {
            /* @TODO: emit XSS detection payload to batch box for dispatch to analytics destination */

            throw new Error(
              'Suspicious Activity: ' +
              event.detail.endpoint +
              ' included, in ' +
              ' [ ' + event.detail.sink + ' ]'
            )
          }
        }
      }

      /* @HINT: When listening to mutation events, might be okay to stagger certain event sequences properly */
      if (canPatchMutationEvent) {
        if (newAttributeValue !== previousAttributeValue) {
    	    const event = window.document.createEvent('MutationEvent')

    	    event.initMutationEvent(
    	      'DOMAttrModified',
    	      true,
    	      false,
    	      self,
    	      previousAttributeValue || '',
    	      newAttributeValue || '',
    	      attributeName,
    	      (previousAttributeValue === null) ? event.ADDITION : event.MODIFICATION
    	    )

    	    self.dispatchEvent(
	          event
	        )
        }
      } else {
        nativeSetAttributeMethod.call(self, attributeName, newAttributeValue)
      }
    }

    /* @HINT: define property `name` on custom function */
    window.Object.defineProperty(window.HTMLElement.prototype.setAttribute, 'name', {
      writable: false,
      value: 'setAttribute'
    })

    /* @HINT: define property function `toString` on custom function */
    window.Object.defineProperty(window.HTMLElement.prototype.setAttribute, 'toString', {
      writable: true,
      value: function toString () {
        return nativeSetAttributeMethod.toString()
      }
    })

    if (isSendBeaconAPISupportedByBrowser()) {
      /* @CHECK: https://developer.mozilla.org/en-US/docs/Web/API/Navigator/sendBeacon */
      window.Navigator.prototype.sendBeacon = function sendBeacon (url, data) {
        /* @HINT: Fire a custom event `beforerequest` to track manual whitelisting of URL endpoints */
        const event = new window.CustomEvent('beforerequest', {
          detail: {
            endpoint: url,
            method: 'POST',
            sink: 'Navigator.sendBeacon',
            data
          },
          bubbles: true,
          cancelable: true
        })

        /* @HINT: Detect if the dispatched custom event was cancelled by a call to `event.preventDefault()` */
        /* @HINT: If the event was cancelled, it means the URL endpoint above was disallowed by the checks */
        const eventWasCancelled = !document.dispatchEvent(event)

        /* @HINT: If it's cancelled, we throw an error to stop the call to `sendBeacon` from being requested */
        if (eventWasCancelled) {
          /* @TODO: emit XSS detection payload to batch box for dispatch to analytics destination */

          throw new Error(
            'Suspicious Activity: ' +
            event.detail.endpoint +
            ' requested, using [ ' + event.detail.data + ' ] in ' +
              ' [ ' + event.detail.sink + ' ] via HTTP ' + event.detail.method
          )
        }

        /* @HINT: If all checks out and no error was thrown above then proceed as usual */
        return nativeSendBeaconFunction.call(this, url, data)
      }

      /* @HINT: define property `name` on custom function */
      window.Object.defineProperty(window.Navigator.prototype.sendBeacon, 'name', {
        writable: false,
        value: 'sendBeacon'
      })

      /* @HINT: define property function `toString` on custom function */
      window.Object.defineProperty(window.Navigator.prototype.sendBeacon, 'toString', {
        writable: true,
        value: function toString () {
          return nativeSendBeaconFunction.toString()
        }
      })

      /* @HINT: Take care of the special Firefox/IceWeasel (Gecko) property `toSource` */
      if ('toSource' in nativeSendBeaconFunction) {
        window.Object.defineProperty(window.Navigator.prototype.sendBeacon, 'toSource', {
          writable: true,
          value: function toSource () {
            return nativeSendBeaconFunction.toSource()
          }
        })
      }
    }

    /* @NOTE: Monkey-patching the `new XMLHttpRequest() .open()` method */
    /* @CHECK: https://developer.mozilla.org/en-US/docs/Web/API/XMLHttpRequest/open */
    window.XMLHttpRequest.prototype.open = function open (method, url, async, user, password) {
      /* @HINT: Fire a custom event `beforerequest` to track manual whitelisting of URL endpoints */
      const event = new window.CustomEvent('beforerequest', {
        detail: {
          endpoint: url,
          method: method.toUpperCase(),
          sink: 'XMLHttpRequest.open',
          data: null
        },
        bubbles: true,
        cancelable: true
      })

      /* @HINT: Detect if the dispatched custom event was cancelled by a call to `event.preventDefault()` */
      /* @HINT: If the event was cancelled, it means the URL endpoint above was disallowed by the checks */
      const eventWasCancelled = !document.dispatchEvent(event)

      /* @HINT: If it's cancelled, we throw an error to stop the call to `sendBeacon` from being requested */
      if (eventWasCancelled) {
        /* @TODO: emit XSS detection payload to batch box for dispatch to analytics destination */
        throw new Error(
          'Suspicious Activity: ' +
          event.detail.endpoint +
          ' requested, using [ ' + event.detail.data + ' ] in ' +
            ' [ ' + event.detail.sink + ' ] via HTTP ' + event.detail.method
        )
      }

      return nativeXHROpenFunction.call(this, method, url, async, user, password)
    }

    /* @HINT: define property `name` on custom function */
    window.Object.defineProperty(window.XMLHttpRequest.prototype.open, 'name', {
      writable: false,
      value: 'open'
    })

    /* @HINT: define property function `toString` on custom function */
    window.Object.defineProperty(window.XMLHttpRequest.prototype.open, 'toString', {
      writable: true,
      value: function toString () {
        return nativeXHROpenFunction.toString()
      }
    })

    /* @NOTE: Monkey-patching the `new Image()` constructor */
    const createImage = function () {
      /* @HINT: Create a new instance of an image DOM element as a baseline */
      const image = new NativeImage()

      /* @HINT: Update the `src` property behaviour for the image DOM element... */
      /* @HINT: ...both when setting and when getting the `src` property */
      const _image = Object.defineProperty(this, 'src', {
        set: function onSet (srcAttr) {
          const url = (srcAttr || '').toString()
          const origin = `${window.location.origin}/`

          /* @HINT: Fire a custom event to track manual whitelisting of URL endpoints */
          const event = new window.CustomEvent('beforerequest', {
            detail: {
              endpoint: url.indexOf('http') === -1 ? origin + url : url,
              method: 'GET',
              sink: 'HTMLImageElement.src',
              data: null
            },
            bubbles: true,
            cancelable: true
          })

          /* @HINT: Detect if the dispatched custom event was cancelled by a call to `event.preventDefault()` */
          /* @HINT: If the event was cancelled, it means the URL endpoint above was disallowed by the checks */
          const eventWasCancelled = !document.dispatchEvent(event)

          /* @HINT: If it's cancelled, we throw an error to stop the image `src` from being requested */
          if (eventWasCancelled) {
            throw new Error(
              'Suspicious Activity: ' +
              event.detail.endpoint +
              ' request, as [ ' + event.detail.method + ' ] in ' +
              ' [ ' + event.detail.sink + ' ]'
            )
          }

          /* @HINT: If all checks out and no error was thrown (or event cancelled) above then proceed as usual */
          image.src = url
        },
        get: function onGet () {
          return image.src
        }
      })

      /* @HINT: Utilize, the JavaScript Proxy to setup wrapped image DOM element */
      /* @CHECK: https://developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Global_Objects/Proxy */
      const _proxy = new Proxy(_image, {
        get: function proxyOnGet (target, prop) {
          let _member = target[prop]

          if (typeof _member === 'function') {
            _member = _member.bind(target)
          }

          return _member
        },
        set: function proxyOnSet (target, prop, value) {
          if (prop === 'src') {
            return (target[prop] = value)
          }

          return (image[prop] = value)
        }
      })

      /* @HINT: Use a symbol to add the name of Image DOM interface `HTMLImageElement` */
      _proxy[Symbol.toStringTag] = image.constructor.name

      /* @HINT: return JavaScript Proxy object */
      return _proxy
    }

    if (/^(?:function)$/.test(typeof NativeImage)) {
      const ProxiedImage = function () {
        return createImage.apply(this, ([]).slice.call(arguments))
      }

      /**
       * !! CAUTION !!
       *
       * - IE `Object.defineProperty` may only work on DOM elements
       */

      /* @HINT: define property `name` on custom function */
      Object.defineProperty(ProxiedImage, 'name', {
        writable: false,
        value: NativeImage.name || 'Image'
      })

      /* @HINT: define property function `toString` on custom function */
      Object.defineProperty(ProxiedImage, 'toString', {
        writable: true,
        value: function toString () {
          return NativeImage.toString()
        }
      })

      /* @HINT: Take care of the special Firefox/IceWeasel (Gecko) property `toSource` */
      if ('toSource' in NativeImage) {
        Object.defineProperty(ProxiedImage, 'toSource', {
          writable: true,
          value: function toSource () {
            return NativeImage.toSource()
          }
        })
      }

      ProxiedImage.prototype[Symbol.toStringTag] = NativeImage.prototype.constructor.name

      window.Image = ProxiedImage
    }
  }
}

/** !
 * @class BotDetector
 *
 *
 * @see https://github.com/RoBYCoNTe/js-bot-detector/blob/master/bot-detector.js
 */
class BotDetector {
  constructor (control) {
  	const self = this

  	this.isBot = false
  	this.tests = {}

  	const selectedTests = control.tests || []

  	if (selectedTests.length === 0 || selectedTests.indexOf(BotDetector.Tests.SCROLL) !== -1) {
  		self.tests[BotDetector.Tests.SCROLL] = function () {
  			const e = function onPageScroll () {
  				self.tests[BotDetector.Tests.SCROLL] = true
  				self.update()
  				self.unbindEvent(window, BotDetector.Tests.SCROLL, e)
  				self.unbindEvent(document, BotDetector.Tests.SCROLL, e)
  			}
  			self.bindEvent(window, BotDetector.Tests.SCROLL, e)
  			self.bindEvent(document, BotDetector.Tests.SCROLL, e)
  		}
  	}

  	if (selectedTests.length === 0 || selectedTests.indexOf(BotDetector.Tests.MOUSE) !== -1) {
  		self.tests[BotDetector.Tests.MOUSE] = function () {
  			const e = function onMouseMove () {
  				self.tests[BotDetector.Tests.MOUSE] = true
  				self.update()
  				self.unbindEvent(window, BotDetector.Tests.MOUSE, e)
  			}
  			self.bindEvent(window, BotDetector.Tests.MOUSE, e)
  		}
  	}

  	if (selectedTests.length === 0 || selectedTests.indexOf(BotDetector.Tests.KEYUP) !== -1) {
  		self.tests[BotDetector.Tests.KEYUP] = function onKeyUp () {
  			const e = function () {
  				self.tests[BotDetector.Tests.KEYUP] = true
  				self.update()
  				self.unbindEvent(window, BotDetector.Tests.KEYUP, e)
  			}
  			self.bindEvent(window, BotDetector.Tests.KEYUP, e)
  		}
  	}

  	if (selectedTests.length === 0 || selectedTests.indexOf(BotDetector.Tests.SWIPE) !== -1) {
  		self.tests[BotDetector.Tests.SWIPE_TOUCHSTART] = function () {
  			const e = function onTouchStart () {
  				self.tests[BotDetector.Tests.SWIPE_TOUCHSTART] = true
  				self.update()
  				self.unbindEvent(document, BotDetector.Tests.SWIPE_TOUCHSTART, onTouchStart)
  			}
  			self.bindEvent(document, BotDetector.Tests.SWIPE_TOUCHSTART, e)
  		}
  	}

  	if (selectedTests.length === 0 || selectedTests.indexOf(BotDetector.Tests.DEVICE_MOTION) !== -1) {
  		self.tests[BotDetector.Tests.DEVICE_MOTION] = function () {
  			const e = function onDeviceMotion (event) {
  				if (event.rotationRate.alpha || event.rotationRate.beta || event.rotationRate.gamma) {
  					const userAgent = navigator.userAgent.toLowerCase()
  					const isAndroid = (('ontouchstart' in document) || ('ontouchstart' in document.documentElement)) && userAgent.indexOf('android') !== -1
  					const beta = isAndroid ? event.rotationRate.beta : Math.round(event.rotationRate.beta / 10) * 10
  					const gamma = isAndroid ? event.rotationRate.gamma : Math.round(event.rotationRate.gamma / 10) * 10

  					if (!self.lastRotationData) {
  						self.lastRotationData = {
  							beta,
  							gamma
  						}
  					} else {
  						let movement = beta !== self.lastRotationData.beta || gamma !== self.lastRotationData.gamma
  						if (isAndroid) {
  							movement = movement && (beta > 0.2 || gamma > 0.2)
  						}
  						// const args = { beta, gamma }
  						self.tests[BotDetector.Tests.DEVICE_MOTION] = movement
  						self.update()
  						if (movement) {
  							self.unbindEvent(window, BotDetector.Tests.DEVICE_MOTION, e)
  						}
  					}
  				} else {
  					self.tests[BotDetector.Tests.DEVICE_MOTION] = false
  				}
  			}
  			self.bindEvent(window, BotDetector.Tests.DEVICE_MOTION, e)
  		}
  	}

  	if (selectedTests.length === 0 || selectedTests.indexOf(BotDetector.Tests.DEVICE_ORIENTATION) !== -1) {
  		self.tests[BotDetector.Tests.DEVICE_ORIENTATION] = function () {
  			const e = function onDeviceOrientation () {
  				self.tests[BotDetector.Tests.DEVICE_ORIENTATION] = true
  				self.update()
  				self.unbindEvent(window, BotDetector.Tests.DEVICE_ORIENTATION, onDeviceOrientation)
  			}
  			self.bindEvent(window, BotDetector.Tests.DEVICE_ORIENTATION, e)
  		}
  	}

  	if (selectedTests.length === 0 || selectedTests.indexOf(BotDetector.Tests.DEVICE_ORIENTATION_MOZ) !== -1) {
  		self.tests[BotDetector.Tests.DEVICE_ORIENTATION_MOZ] = function () {
  			const e = function moz_onDeviceOrientation () {
  				self.tests[BotDetector.Tests.DEVICE_ORIENTATION_MOZ] = true
  				self.update()
  				self.unbindEvent(window, BotDetector.Tests.DEVICE_ORIENTATION_MOZ, moz_onDeviceOrientation)
  			}
  			self.bindEvent(window, BotDetector.Tests.DEVICE_ORIENTATION_MOZ, e)
  		}
  	}

  	self.cases = {}
  	self.timeout = control.timeout || 1000
  	self.callback = control.callback || null
  	self.detected = false
  }
}

BotDetector.Tests = {
  KEYUP: 'keyup',
  MOUSE: 'mousemove',
  SWIPE: 'swipe',
  SWIPE_TOUCHSTART: 'touchstart',
  SWIPE_TOUCHMOVE: 'touchmove',
  SWIPE_TOUCHEND: 'touchend',
  SCROLL: 'scroll',
  GESTURE: 'gesture',
  GYROSCOPE: 'gyroscope',
  DEVICE_MOTION: 'devicemotion',
  DEVICE_ORIENTATION: 'deviceorientation',
  DEVICE_ORIENTATION_MOZ: 'MozOrientation'
}

BotDetector.prototype.update = function (canNotify = false) {
  const self = this

  let count = 0
  let tests = 0

  for (const testCount in self.tests) {
    if (self.tests.hasOwnProperty(testCount)) {
      self.cases[testCount] = self.tests[testCount] === true
      if (self.cases[testCount] === true) {
        count++
      }
    }
    tests++
  }

  self.isBot = count === 0
  self.allMatched = count === tests
  if (canNotify) {
    self.callback(self)
  }
}

BotDetector.prototype.bindEvent = function (root, type, handler) {
  if (root.addEventListener) {
    root.addEventListener(type, handler, false)
  } else if (root.attachEvent) {
    root.attachEvent('on' + type, handler)
  }
}

BotDetector.prototype.unbindEvent = function (root, type, handle) {
  if (root.removeEventListener) {
    root.removeEventListener(type, handle, false)
  } else {
    const evtName = 'on' + type
    if (root.detachEvent) {
      if (typeof root[evtName] !== 'undefined') {
        root[type] = null
      }
      root.detachEvent(evtName)
    }
  }
}

BotDetector.prototype.initialize = function () {
  const self = this

  for (const testCount in this.tests) {
    if (this.tests.hasOwnProperty(testCount)) {
      this.tests[testCount].call()
    }
  }

  this.update()

  window.setTimeout(() => {
    self.update(true)
  }, self.timeout)

  return self
}

/** !
 * @class NavigatorMetricsTracker
 *
 *
 *
 */

class NavigatorMetricsTracker {
  constructor (maxMeasureTime = 15000, resourceTiming = true, elementTiming = true) {
    const perfume = new Perfume({
      resourceTiming,
      elementTiming,
      maxMeasureTime,
      analyticsTracker: (options) => {
        const { metricName, data /*, navigatorInformation */ } = options
        switch (metricName) {
          case 'navigationTiming':
            if (data && data.timeToFirstByte) {
              window.dispatchEvent(new CustomEvent('agentmetricavailable', {
                detail: {
                  metric: 'navigationTiming',
                  payload: data
                },
                bubbles: true,
                cancelable: true
              }))
            }
            break
          case 'networkInformation':
            if (data && data.effectiveType) {
              window.dispatchEvent(new CustomEvent('agentmetricavailable', {
                detail: {
                  metric: 'networkInformation',
                  payload: data
                },
                bubbles: true,
                cancelable: true
              }))
            }
            break
          case 'fp':
            window.dispatchEvent(new CustomEvent('agentmetricavailable', {
              detail: {
                metric: 'firstPaint',
                payload: { duration: data }
              },
              bubbles: true,
              cancelable: true
            }))
            break
          case 'fcp':
            window.dispatchEvent(new CustomEvent('agentmetricavailable', {
              detail: {
                metric: 'firstContentfulPaint',
                payload: { duration: data }
              },
              bubbles: true,
              cancelable: true
            }))
            break
          case 'fid':
            window.dispatchEvent(new CustomEvent('agentmetricavailable', {
              detail: {
                metric: 'firstInputDelay',
                payload: { duration: data }
              },
              bubbles: true,
              cancelable: true
            }))
            break
          case 'lcp':
            window.dispatchEvent(new CustomEvent('agentmetricavailable', {
              detail: {
                metric: 'largestContentfulPaint',
                payload: { duration: data }
              },
              bubbles: true,
              cancelable: true
            }))
            break
          case 'cls':
            window.dispatchEvent(new CustomEvent('agentmetricavailable', {
              detail: {
                metric: 'cumulativeLayoutShift',
                payload: { duration: data }
              },
              bubbles: true,
              cancelable: true
            }))
            break
          case 'clsFinal':
            window.dispatchEvent(new CustomEvent('agentmetricavailable', {
              detail: {
                metric: 'cumulativeLayoutShiftFinal',
                payload: { duration: data }
              },
              bubbles: true,
              cancelable: true
            }))
            break
          case 'tbt':
            window.dispatchEvent(new CustomEvent('agentmetricavailable', {
              detail: {
                metric: 'totalBlockingTime',
                payload: { duration: data }
              },
              bubbles: true,
              cancelable: true
            }))
            break
          default:
            window.dispatchEvent(new CustomEvent('agentmetricavailable', {
              detail: {
                metric: metricName,
                payload: typeof data === 'number' ? { duration: data } : data
              },
              bubbles: true,
              cancelable: true
            }))
            break
        }
      }
    })
    this.tracker = perfume
  }
}

let botDetector = null
let xssDetector = null
let navigatorMetricsTracker = null

export const module = {
  initializeBotDetector: (botCheckTimeout = 1000) => {
    if (botDetector === null) {
      botDetector = new BotDetector({
        timeout: botCheckTimeout,
        callback: function (result) {
          if (result.isBot) {
            window.dispatchEvent(new CustomEvent('agentbotactivity', {
              detail: {
                captured: result.allMatched,
                cases: result.cases
              },
              bubbles: true,
              cancelable: true
            }))
          }
        }
      }).initialize()
    }
    return {
      getInstance () {
        throw new Error('instance not publicly accessible')
      },
      destroy () {
        botDetector = null
      }
    }
  },
  initializeXSSDetector: (whitelistedURLs = [], urlsCheckCallback) => {
    if (xssDetector === null) {
      xssDetector = new XSSDetector(
        whitelistedURLs,
        urlsCheckCallback
      ).initialize()
    }
    return {
      getInstance () {
        throw new Error('instance not publicly accessible')
      },
      destroy () {
        xssDetector = null
      }
    }
  },
  initializeNavigatorMetricsTracker: (maxMeasureTime, resourceTiming, elementTiming) => {
    if (navigatorMetricsTracker === null) {
      navigatorMetricsTracker = new NavigatorMetricsTracker(
        resourceTiming, elementTiming, maxMeasureTime
      )
    }
    return {
      getInstance () {
        return navigatorMetricsTracker.tracker
      },
      destroy () {
        navigatorMetricsTracker.tracker = null
        navigatorMetricsTracker = null
      }
    }
  }
}
