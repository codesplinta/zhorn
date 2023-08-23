import { trustedTypes } from "trusted-types";
import URISanity from "urisanity";
import DOMPurify from "dompurify";
import Perfume from "perfume.js";

const isSafariBrowser = ("gesturechange" in window);
/* @HINT: Detect whether the browser executing this script is old IE (Trident rendering engine); IE6 - IE11 */
const isTrident_IE = (/*@cc_on!@*/false || window.document.uniqueID || window.document.createEventObject) 
  && (window.toStaticHTML || ((document.documentMode >= 9) && ("clientInformation" in window)));

/* @HINT: */
const attrModifiedMutationEventDoesntWork = () => {
  const attrModifiedListenerCalled = false;
	  
	const attrModifiedListener = function () {
    attrModifiedListenerCalled = true;
  };

	window.document.documentElement.addEventListener(
    "DOMAttrModified", attrModifiedListener, false
  );
	window.document.documentElement.setAttribute("___TEST___", true);
	window.document.documentElement.removeAttribute("___TEST___", true);
	window.document.documentElement.removeEventListener(
    "DOMAttrModified", attrModifiedListener, false
  );
	
	return attrModifiedListenerCalled === false;
};

/* @HINT: Detect whether the browser executing this script has support for `window.navigator.sendBeacon()`*/
const isSendBeaconAPISupported = () => {
  return (window.navigator && ("sendBeacon" in window.navigator));
};


/**!
 * class XSSDetector
 *
 *
 */
class XSSDetector {
  constructor (whitelistedURLs = [], urlsCheckCallback = () => undefined) {
    this.whitelistedURLs = whitelistedURLs;
    this.urlsCheckCallback = urlsCheckCallback;

    /* @HINT: Trusted Types object reference */
    /* @CHECK: https://developer.mozilla.org/en-US/docs/Web/API/Trusted_Types_API */
    let TT;
    
    /* @HINT: feature / object detection */
    if (typeof window.trustedTypes === "undefined") {
      TT = trustedTypes;
    } else {
      TT = window.trustedTypes;
    }

    /* @HINT: Setup event handler for Content Security Policy violation */
    /* @CHECK: https://developer.mozilla.org/en-US/docs/Web/API/Element/securitypolicyviolation_event */
    window.addEventListener(
      "securitypolicyviolation",
      window.console.error.bind(window.console)
    );
    
    TT.createPolicy("default", {
      createHTML: (html) => {
        if (!TT.isHTML(html)) {
          window.console.error(new CustomEvent("untrusted html detected"));
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
          ADD_TAGS: ["trix-editor"], /* @HINT: Add Basecamp's Trix Editor special tag */
          ADD_ATTR: ["nonce", "sha257", "target", "aria-x-fillable"], /* @HINT: for Link(-able) Elements / Content-Security-Policy internal <script> / <style> tags */
          KEEP_CONTENT: false,
          ADD_DATA_URI_TAGS: ["a", "area"],
          ALLOW_ARIA_ATTR: true, /* @HINT: Enable accessibility attributes */
          IN_PLACE: true,
          ALLOW_DATA_ATTR: true,
          FORBID_ATTR: ["ping", "inert"], /* @HINT: Disallow `ping` attribute on anchors; <a ping="http://example.com/impressions"></a> */
          SAFE_FOR_JQUERY: true,
          FORBID_CONTENTS: ["img"],
          FORBID_TAGS: ["a"],
          SANITIZE_NAMED_PROPS: true,
          ADD_URI_SAFE_ATTR: ["href", "src"]
        });
      },
      createScriptURL: (url) => {
        if (!TT.isScriptURL(url)) {
          window.console.error(new CustomEvent("untrusted script url detected"));
        }
        /* @HINT: 
          
          vet URL string and return "about:blank" if URL string is suspicious
        */
        return URISanity.vet(url, {
          allowWebTransportURI: true,
          allowScriptOrDataURI: true
        });
      }
    });
  }

  initialize () {
    const whitelistedURLs = this.whitelistedURLs;
    const urlsCheckCallback = this.urlsCheckCallback;

    /* @HINT: Setting custome events to check and validate URLs */
    window.document.addEventListener( "beforerequest", onBeforeURIUsed, false );
    window.document.addEventListener( "beforeinclude", onBeforeURIUsed, false );

    
    /* @HINT: Event handler common to the two events above */
    function onBeforeURIUsed ( event ) {
      /* @HINT: Vet the URL endpoint being requested/included for safety */
      if (URISanity.vet(
        event.detail.endpoint,
        { allowWebTransportURI: true }
      ) !== "about:blank") {
        const { origin, pathname } = new URL(event.detail.endpoint);
    
        /* @HINT: Make sure the endpoint being requested/included is part of the whitelist */
        if (whitelistedURLs.includes(`${origin}${pathname}`)) {
          try {
            urlsCheckCallback(
              Urisanity,
              event.detail
            );
          } catch (error) {
            if (error instanceof Error) {
              event.preventDefault();
            }
          }
          return true;
        }
      }
    
      /* @HINT: trigger an error to be thrown when the endpoint is not in the whitelist above */
      /* @HINT: Or the validation above for any origin + pathname doesn't pass */
      event.preventDefault();
    }
  }

  monkeyPatchDOMInterfaces () {
    const canPatchMutationEvent = (typeof window.MutationObserver !== "function")
      && attrModifiedMutationEventDoesntWork();

    /* @HINT: craete a function/constructor that does nothing a.k.a no-operation function */
    const noop = function noOperation () {}

    /* @HINT: Extract the native definitions of these APIs from the DOM Interfaces */
    const nativeSetAttributeMethod = HTMLElement.prototype.setAttribute || noop;
    const nativeRemoveAttributeMethod = HTMLElement.prototype.removeAttribute || noop;
    /* @HINT: Copy out the user-agent interface function `sendBeacon` */
    const nativeSendBeaconFunction = window.Navigator.prototype.sendBeacon || noop
    /* @HINT: */
    const nativeHrefAttributePropertySetter = window.Object.prototype.__lookupSetter__.call(
      HTMLAnchorElement.prototype,
      "href"
    );

    /* @HINT: Create a new definition for `setAttribute` that instruments the API to detect suspicious URIs */
    HTMLElement.prototype.setAttribute = function setAttribute (attributeName, newValue) {
  	  const self = this;
  	  const previousValue = self.getAttribute(attributeName);
  
  	  let timerID = null;

      if (canPatchMutationEvent) {
        timerID = window.setTimeout(function () { 
          /* @HINT: Stop [ DOMSubtreeModified ] event from firing before [ DOMAttrModified ] event */
    		  nativeSetAttributeMethod.call(that, attributeName, newValue);
    	  }, 0);
      }
  
      /* @HINT: Whenever the attribute name is `href`, then check the URL that is the value */
      if (attributeName === "href" || attributeName === "src") {
        /* @HINT: Fire a custom event `beforeinclude` to track manual whitelisting of URL endpoints */
        let event = new window.CustomEvent("beforeinclude", {
          detail: {
            endpoint: newValue,
            method: undefined,
            sink: "HTMLElement.setAttribute",
            data: null
          },
          bubbles: true,
          cancelable: true
        });
  
        /* @HINT: Detect if the dispatched custom event was cancelled by a call to `event.preventDefault()` */
        /* @HINT: If the event was cancelled, it means the URL endpoint above was disallowed by the checks */
        const eventWasCancelled = !window.document.dispatchEvent(event);
  
       /* @HINT: If it's cancelled, stop the `setTimeout` call above from being executed by clearing the timeout */
       /* @HINT: Also, we throw an error to stop the call to `setAttribute` from being requested */
       if (eventWasCancelled) {
         if (timerID !== null) {
           window.clearTimeout(timerID);
         }

         /* @TODO: emit XSS detection payload to batch box for dispatch to analytics destination */

         throw new Error(
           "Suspicious Activity: "
           +
           event.detail.endpoint
           +
           " included, in "
           +
           " [ " + event.detail.sink + " ]"
         )
        } else {
          if (!DOMPurify.isValidAttribute(self.tagName.toLowerCase(), attributeName, event.detail.endpoint)) {

            /* @TODO: emit XSS detection payload to batch box for dispatch to analytics destination */

            throw new Error(
             "Suspicious Activity: "
             +
             event.detail.endpoint
             +
             " included, in "
             +
             " [ " + event.detail.sink + " ]"
           )
          }
        }
      }
  
      /* @HINT: When listening to mutation events, might be okay to stagger certain event sequences properly */
  	  if (canPatchMutationEvent) {
        if (newValue !== previousValue) {
    	    let event = document.createEvent("MutationEvent");
    	    event.initMutationEvent(
    	      "DOMAttrModified",
    	      true,
    	      false,
    	      self,
    	      previousValue || "",
    	      newValue || "",
    	      attributeName,
    	      (previousValue === null) ? event.ADDITION : event.MODIFICATION
    	    );
    		  
    	    self.dispatchEvent(
            event
          );
        }
  	  } else {
        nativeSetAttributeMethod.call(self, attributeName, newValue);
      }
  	};

    /* @HINT: define property `name` on custom function */
    window.Object.defineProperty(setAttribute, "name", {
      writable: false,
      value: "setAttribute"
    });
      
    /* @HINT: define property function `toString` on custom function */
    window.Object.defineProperty(setAttribute, "toString", {
      writable: true,
      value: function toString () {
        return nativeSetAttributeMethod.toString()
      }
    });

    window.Navigator.prototype.sendBeacon = function sendBeacon (url, data) {
      /* @HINT: Fire a custom event `beforerequest` to track manual whitelisting of URL endpoints */
      const event = new window.CustomEvent("beforerequest", {
        detail: {
          endpoint: url,
          method: "POST",
          sink: "Navigator.sendBeacon",
          data: data
        },
        bubbles: true,
        cancelable: true
      });
    
      /* @HINT: Detect if the dispatched custom event was cancelled by a call to `event.preventDefault()` */
      /* @HINT: If the event was cancelled, it means the URL endpoint above was disallowed by the checks */
      const eventWasCancelled = !document.dispatchEvent(event)
    
       /* @HINT: If it's cancelled, we throw an error to stop the call to `sendBeacon` from being requested */
       if (eventWasCancelled) {

         /* @TODO: emit XSS detection payload to batch box for dispatch to analytics destination */

         throw new Error(
           "Suspicious Activity: "
           +
           event.detail.endpoint
           +
           " requested, using [ " + event.detail.data + " ] in "
            +
            " [ " + event.detail.sink + " ] via HTTP " + event.detail.method
         )
       }
    
       /* @HINT: If all checks out and no error was thrown above then proceed as usual */
       return nativeSendBeaconFunction.call(this, url, data);
    };
      
    /* @HINT: define property `name` on custom function */
    window.Object.defineProperty(sendBeacon, "name", {
      writable: false,
      value: "sendBeacon"
    });
      
    /* @HINT: define property function `toString` on custom function */
    window.Object.defineProperty(sendBeacon, "toString", {
      writable: true,
      value: function toString () {
        return nativeSendBeaconFunction.toString()
      }
    });
      
    /* @HINT: Take care of the special Firefox/IceWeasel (Gecko) property `toSource` */
    if ("toSource" in nativeSendBeaconFunction) {
      window.Object.defineProperty(sendBeacon, "toSource", {
        writable: true,
        value: function toSource () {
          return nativeSendBeaconFunction.toSource()
        }
      });
    }
  }
}


/**!
 * class BotDetector
 *
 *
 * @see https://github.com/RoBYCoNTe/js-bot-detector/blob/master/bot-detector.js
 */
class BotDetector {
  constructor (control) {
  	const self = this;

  	this.isBot = false;
  	this.tests = {};
  
  	const selectedTests = control.tests || [];
  
  	if (selectedTests.length === 0 || selectedTests.indexOf(BotDetector.Tests.SCROLL) !== -1) {
  		self.tests[BotDetector.Tests.SCROLL] = function () {
  			const e = function onPageScroll () {
  				self.tests[BotDetector.Tests.SCROLL] = true;
  				self.update()
  				self.unbindEvent(window, BotDetector.Tests.SCROLL, e)
  				self.unbindEvent(document, BotDetector.Tests.SCROLL, e)
  			};
  			self.bindEvent(window, BotDetector.Tests.SCROLL, e);
  			self.bindEvent(document, BotDetector.Tests.SCROLL, e);
  		};
  	}
  
  	if (selectedTests.length === 0 || selectedTests.indexOf(BotDetector.Tests.MOUSE) !== -1) {
  		self.tests[BotDetector.Tests.MOUSE] = function () {
  			const e = function onMouseMove () {
  				self.tests[BotDetector.Tests.MOUSE] = true;
  				self.update();
  				self.unbindEvent(window, BotDetector.Tests.MOUSE, e);
  			}
  			self.bindEvent(window, BotDetector.Tests.MOUSE, e);
  		};
  	}
  
  	if (selectedTests.length === 0 || selectedTests.indexOf(BotDetector.Tests.KEYUP) !== -1) {
  		self.tests[BotDetector.Tests.KEYUP] = function onKeyUp () {
  			const e = function() {
  				self.tests[BotDetector.Tests.KEYUP] = true;
  				self.update();
  				self.unbindEvent(window, BotDetector.Tests.KEYUP, e);
  			}
  			self.bindEvent(window, BotDetector.Tests.KEYUP, e);
  		};	
  	}
  
  	if (selectedTests.length === 0 || selectedTests.indexOf(BotDetector.Tests.SWIPE) !== -1) {
  		self.tests[BotDetector.Tests.SWIPE_TOUCHSTART] = function () {
  			const e = function onTouchStart () {
  				self.tests[BotDetector.Tests.SWIPE_TOUCHSTART] = true;
  				self.update();
  				self.unbindEvent(document, BotDetector.Tests.SWIPE_TOUCHSTART);
  			}
  			self.bindEvent(document, BotDetector.Tests.SWIPE_TOUCHSTART);
  		}
  	}
  
  	if (selectedTests.length === 0 || selectedTests.indexOf(BotDetector.Tests.DEVICE_MOTION) !== -1) {
  		self.tests[BotDetector.Tests.DEVICE_MOTION] = function () {
  			const e = function onDeviceMotion (event) {
  				if(event.rotationRate.alpha || event.rotationRate.beta || event.rotationRate.gamma) {
  					const userAgent = navigator.userAgent.toLowerCase();
  					const isAndroid = (('ontouchstart' in document) || ('ontouchstart' in document.documentElement)) && userAgent.indexOf("android") !== -1;
  					const beta = isAndroid ? event.rotationRate.beta : Math.round(event.rotationRate.beta / 10) * 10;
  					const gamma = isAndroid ? event.rotationRate.gamma : Math.round(event.rotationRate.gamma / 10) * 10;

  					if (!self.lastRotationData) {
  						self.lastRotationData = {
  							beta: beta,
  							gamma: gamma
  						};
  					} else {
  						let movement = beta !== self.lastRotationData.beta || gamma !== self.lastRotationData.gamma;
  						if (isAndroid) {
  							movement = movement && (beta > 0.2 || gamma > 0.2);
  						}
  						let args = { beta: beta, gamma: gamma };
  						self.tests[BotDetector.Tests.DEVICE_MOTION] = movement;
  						self.update();
  						if (movement) {
  							self.unbindEvent(window, BotDetector.Tests.DEVICE_MOTION, e);		
  						}
  					}
  				} else {
  					self.tests[BotDetector.Tests.DEVICE_MOTION] = false;
  				}
  				
  			}
  			self.bindEvent(window, BotDetector.Tests.DEVICE_MOTION, e);
  		}
  	}
  
  	if (selectedTests.length === 0 || selectedTests.indexOf(BotDetector.Tests.DEVICE_ORIENTATION) !== -1) {
  		self.tests[BotDetector.Tests.DEVICE_ORIENTATION] = function() {
  			const e = function onDeviceOrientation () {
  				self.tests[BotDetector.Tests.DEVICE_ORIENTATION] = true;
  				self.update();
  				self.unbindEvent(window, BotDetector.Tests.DEVICE_ORIENTATION, e);
  			}
  			self.bindEvent(window, BotDetector.Tests.DEVICE_ORIENTATION, e);
  		}
  	}

  	if (selectedTests.length === 0 || selectedTests.indexOf(BotDetector.Tests.DEVICE_ORIENTATION_MOZ) !== -1) {
  		self.tests[BotDetector.Tests.DEVICE_ORIENTATION_MOZ] = function() {
  			const e = function moz_onDeviceOrientation () {
  				self.tests[BotDetector.Tests.DEVICE_ORIENTATION_MOZ] = true;
  				self.update();
  				self.unbindEvent(window, BotDetector.Tests.DEVICE_ORIENTATION_MOZ);
  			}
  			self.bindEvent(window, BotDetector.Tests.DEVICE_ORIENTATION_MOZ);
  		}
  	}
  
  
  	self.cases = {};
  	self.timeout = control.timeout || 1000;
  	self.callback = control.callback || null;
  	self.detected = false;
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
};

BotDetector.prototype.update = function(canNotify =  false) {
	const self = this;

	let count = 0;
	let tests = 0;

	for(let testCount in self.tests) {
		if (self.tests.hasOwnProperty(i)) {
			self.cases[testCount] = self.tests[testCount] === true;
			if (self.cases[testCount] === true) {
				count++;
			}
		}
		tests++;
	}

	self.isBot = count === 0;
	self.allMatched = count === tests;
	if (canNotify) {
		self.callback(self);
	}
}

BotDetector.prototype.bindEvent = function (root, type, handler) {
	if (root.addEventListener) {
		root.addEventListener(type, handler, false);
	} else if (root.attachEvent) {
		root.attachEvent("on" + type, handler);
	}
};

BotDetector.prototype.unbindEvent = function (root, type, handle) {
	if (root.removeEventListener) {
		root.removeEventListener(type, handle, false);
	} else {
		const evtName = "on" + type;
		if (root.detachEvent) {
			if (typeof root[evtName] !== 'undefined') {
				root[type] = null
			}
			root.detachEvent(evtName);
		}
	}
};

BotDetector.prototype.monitor = function () {
	const self = this;

	for(let testCount in this.tests) {
		if (this.tests.hasOwnProperty(testCount)) {
			this.tests[testCount].call();
		}
	}

	this.update(false);

	window.setTimeout(() => {
		self.update(true);
	}, self.timeout);
};

/**!
 *
 *
 *
 */
const perfume = new Perfume({
  resourceTiming: true,
  elementTiming: true,
  analyticsTracker: (options) => {
    const { metricName, data, navigatorInformation } = options;
    switch (metricName) {
      case "navigationTiming":
        if (data && data.timeToFirstByte) {
          myAnalyticsTool.track("navigationTiming", data);
        }
        break;
      case "networkInformation":
        if (data && data.effectiveType) {
          myAnalyticsTool.track("networkInformation", data);
        }
        break;
      case "fp":
        myAnalyticsTool.track("firstPaint", { duration: data });
        break;
      case "fcp":
        myAnalyticsTool.track("firstContentfulPaint", { duration: data });
        break;
      case "fid":
        myAnalyticsTool.track("firstInputDelay", { duration: data });
        break;
      case "lcp":
        myAnalyticsTool.track("largestContentfulPaint", { duration: data });
        break;
      case "cls":
        myAnalyticsTool.track("cumulativeLayoutShift", { duration: data });
        break;
      case "clsFinal":
        myAnalyticsTool.track("cumulativeLayoutShiftFinal", { duration: data });
        break;
      case "tbt":
        myAnalyticsTool.track("totalBlockingTime", { duration: data });
        break;
      default:
        myAnalyticsTool.track(metricName, { duration: data });
        break;
    }
  },
});

new BotDetector({
  timeout: 1000,
  callback: function(result) {
    if (result.isBot) {
      window.dispatchEvent(new CustomEvent("botactivity"));
    }
  }
}).monitor();
