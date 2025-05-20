window.performanceMonitor = {
  frameCount: 0,
  lastFrameTime: performance.now(),
  lowPerformanceMode: false,
  animationFrame: null,
  isRunning: false,

  measure: function () {
    try {
      if (!this.isRunning) return;

      const now = performance.now();
      const elapsed = now - this.lastFrameTime;
      this.frameCount++;

      if (elapsed >= 1000) {
        const fps = Math.round((this.frameCount * 1000) / elapsed);

        // Performance thresholds
        if (fps < 30 && !this.lowPerformanceMode) {
          this.enableLowPerformanceMode();
        } else if (fps >= 45 && this.lowPerformanceMode) {
          this.disableLowPerformanceMode();
        }

        // Reset counters
        this.frameCount = 0;
        this.lastFrameTime = now;
      }

      this.animationFrame = requestAnimationFrame(() => this.measure());
    } catch (error) {
      console.error("Error in performance monitoring:", error);
      this.stop(); // Stop on error to prevent infinite error loops

      // Fallback to reduced animations
      document.body.classList.add("reduce-animations");
    }
  },

  start: function () {
    if (this.isRunning) return;

    this.isRunning = true;
    this.frameCount = 0;
    this.lastFrameTime = performance.now();

    // Cancel any existing animation frame
    if (this.animationFrame) {
      cancelAnimationFrame(this.animationFrame);
    }

    this.measure();
  },

  stop: function () {
    this.isRunning = false;
    if (this.animationFrame) {
      cancelAnimationFrame(this.animationFrame);
      this.animationFrame = null;
    }
  },

  enableLowPerformanceMode: function () {
    this.lowPerformanceMode = true;
    document.body.classList.add("reduce-animations");
  },

  disableLowPerformanceMode: function () {
    this.lowPerformanceMode = false;
    document.body.classList.remove("reduce-animations");
  },
};

// === LOADING STATE MANAGEMENT === //
window.loadingStateManager = {
  elements: new Map(),

  startLoading: function (element, timeoutMs = 8000) {
    if (!element) return;

    // Clear any existing timeout for this element
    if (this.elements.has(element)) {
      clearTimeout(this.elements.get(element));
    }

    // Add loading state with a single reflow
    requestAnimationFrame(() => {
      element.classList.add("loading-state");
      element.setAttribute("aria-busy", "true");
    });

    // Set timeout to prevent indefinite loading states
    const timeoutId = setTimeout(() => {
      this.stopLoading(element);
    }, timeoutMs);

    this.elements.set(element, timeoutId);
  },

  stopLoading: function (element) {
    if (!element) return;

    // Clear any existing timeout for this element
    if (this.elements.has(element)) {
      clearTimeout(this.elements.get(element));
      this.elements.delete(element);
    }

    requestAnimationFrame(() => {
      element.classList.remove("loading-state");
      element.removeAttribute("aria-busy");
    });
  },

  reset: function () {
    for (const [element, timeoutId] of this.elements.entries()) {
      clearTimeout(timeoutId);
      element.classList.remove("loading-state");
      element.removeAttribute("aria-busy");
    }
    this.elements.clear();
  },
};

// Define cleanupManager for resource management
window.cleanupManager = {
  observers: [],
  timeouts: [],
  animationFrame: null,
  performanceMonitorRegistered: false,

  registerPerformanceMonitor: function () {
    if (this.performanceMonitorRegistered) return;

    try {
      if (
        window.performanceMonitor &&
        window.performanceMonitor.animationFrame
      ) {
        this.animationFrame = window.performanceMonitor.animationFrame;
        this.performanceMonitorRegistered = true;
        console.debug(
          "Successfully registered performance monitor for cleanup"
        );
      }
    } catch (error) {
      console.error("Error registering performance monitor:", error);
      document.body.classList.add("reduce-animations");
    }
  },

  registerObserver: function (observer) {
    if (observer && typeof observer.disconnect === "function") {
      this.observers.push(observer);
    }
  },

  registerTimeout: function (timeoutId) {
    if (timeoutId) {
      this.timeouts.push(timeoutId);
    }
  },

  cleanup: function () {
    // Disconnect all observers
    this.observers.forEach((observer) => {
      try {
        if (observer && typeof observer.disconnect === "function") {
          observer.disconnect();
        }
      } catch (error) {
        console.warn("Error disconnecting observer:", error);
      }
    });

    // Clear all timeouts
    this.timeouts.forEach((timeoutId) => {
      clearTimeout(timeoutId);
    });

    // Cancel animation frame if exists
    if (this.animationFrame) {
      cancelAnimationFrame(this.animationFrame);
      this.animationFrame = null;
    }

    // Reset loading states
    if (window.loadingStateManager) {
      window.loadingStateManager.reset();
    }

    // Reset state
    this.observers = [];
    this.timeouts = [];
  },
};

document.addEventListener("DOMContentLoaded", function () {
  // Define utility functions at the global scope

  // Register performance monitor with cleanup manager
  cleanupManager.registerPerformanceMonitor();

  // Helper function to create error boundaries for event handlers
  window.withErrorBoundary = function (fn, context) {
    return function (...args) {
      try {
        return fn.apply(this, args);
      } catch (error) {
        console.error(`Error in ${context}:`, error);
        // Restore the element to a clean state
        if (this && this.classList) {
          this.classList.remove(
            "loading-state",
            "processing",
            "cart-updated",
            "cart-error"
          );
        }
      }
    };
  };

  // Debounce function to limit function calls
  window.debounce = function (func, wait) {
    let timeout;
    return function executedFunction(...args) {
      const later = () => {
        clearTimeout(timeout);
        func(...args);
      };
      clearTimeout(timeout);
      timeout = setTimeout(later, wait);
    };
  };

  // === 1. SCROLL-TRIGGERED ANIMATIONS ===
  initScrollAnimations();

  // === 2. TOUCH FEEDBACK ENHANCEMENTS ===
  initTouchFeedback();

  // === 3. SMOOTH STATE TRANSITIONS ===
  initStateTransitions();

  // === 4. LOADING STATE MANAGEMENT ===
  initLoadingStates();

  // === 5. CART ANIMATIONS AND INTERACTIONS ===
  initCartAnimations();

  // === 6. ADDITIONAL ENHANCEMENTS ===
  initAdditionalEnhancements();

  // Start performance monitoring with proper initialization check
  try {
    if (!window.performanceMonitor) {
      console.warn("Performance monitor not initialized");
      // Initialize default state
      document.body.classList.add("reduce-animations");
    } else {
      // Check for battery API to reduce animations on low battery
      if ("getBattery" in navigator) {
        navigator
          .getBattery()
          .then((battery) => {
            if (battery.level < 0.15 && !battery.charging) {
              console.info("Low battery detected, reducing animations");
              document.body.classList.add("reduce-animations");
            } else {
              window.performanceMonitor.start();
            }
          })
          .catch(() => {
            // Start performance monitor if battery API fails
            window.performanceMonitor.start();
          });
      } else {
        window.performanceMonitor.start();
      }
    }
  } catch (error) {
    console.error("Failed to start performance monitoring:", error);
    // Fallback to reduced animations
    document.body.classList.add("reduce-animations");
  }
});

// === PERFORMANCE OPTIMIZATIONS === //

// 1. Optimized intersection observer options
const optimizedObserverOptions = {
  threshold: 0.15,
  rootMargin: "50px 0px",
  root: null,
};

// Initialize optimized observer for animations
const optimizedObserver = new IntersectionObserver((entries) => {
  entries.forEach((entry) => {
    if (entry.isIntersecting) {
      requestAnimationFrame(() => {
        try {
          entry.target.classList.add("visible");

          // Apply staggered animation to children
          const animatableChildren =
            entry.target.querySelectorAll("img, .image");
          animatableChildren.forEach((child, index) => {
            child.style.transitionDelay = `${index * 100}ms`;
          });
        } catch (error) {
          console.error("Error applying optimized animation:", error);
        }
      });

      // Once animation is complete, unobserve the element
      try {
        optimizedObserver.unobserve(entry.target);
      } catch (error) {
        console.error("Error unobserving element:", error);
      }
    }
  });
}, optimizedObserverOptions);

// 2. Improved scroll performance with throttling
const throttleScroll = (() => {
  let waiting = false;
  return function () {
    if (!waiting) {
      waiting = true;
      requestAnimationFrame(() => {
        document.body.classList.toggle("is-scrolling", window.scrollY > 0);
        waiting = false;
      });
    }
  };
})();

// Use the optimized scroll handler with passive option for better performance
window.addEventListener("scroll", throttleScroll, { passive: true });

// Optimize animation performance with will-change
const optimizeAnimationPerformance = () => {
  // Apply will-change to elements that animate frequently
  const animatedElements = document.querySelectorAll(
    ".cont, .modal, .addToCart, .image"
  );

  animatedElements.forEach((element) => {
    // Apply will-change property for hardware acceleration
    element.style.willChange = "transform, opacity";

    // Clean up will-change after animations complete to free resources
    const cleanupWillChange = () => {
      requestAnimationFrame(() => {
        element.style.willChange = "auto";
      });
    };

    element.addEventListener("transitionend", cleanupWillChange, {
      once: true,
    });
    element.addEventListener("animationend", cleanupWillChange, { once: true });
  });
};

// Re-apply optimizations when new content is added
const mutationObserver = new MutationObserver((mutations) => {
  let hasNewNodes = false;

  mutations.forEach((mutation) => {
    if (mutation.addedNodes.length > 0) {
      hasNewNodes = true;
    }
  });

  if (hasNewNodes) {
    optimizeAnimationPerformance();
  }
});

// Observe DOM changes
mutationObserver.observe(document.body, {
  childList: true,
  subtree: true,
});

// 3. Enhanced touch detection and behavior
const isTouchDevice = () => {
  return (
    "ontouchstart" in window ||
    navigator.maxTouchPoints > 0 ||
    navigator.msMaxTouchPoints > 0
  );
};

if (isTouchDevice()) {
  document.body.classList.add("touch-device");

  // Optimize touch feedback without layout thrashing
  const addOptimizedTouchFeedback = (elements) => {
    elements.forEach((element) => {
      element.addEventListener(
        "touchstart",
        function () {
          this.setAttribute("data-touch-active", "true");
          requestAnimationFrame(() => {
            this.classList.add("touch-active");
          });
        },
        { passive: true }
      );

      ["touchend", "touchcancel"].forEach((eventType) => {
        element.addEventListener(
          eventType,
          function () {
            this.removeAttribute("data-touch-active");
            requestAnimationFrame(() => {
              this.classList.remove("touch-active");
            });
          },
          { passive: true }
        );
      });
    });
  };

  // Apply to all interactive elements
  addOptimizedTouchFeedback(
    document.querySelectorAll(
      ".addToCart, button, .signButton, #searchBtn, #subscribeButton, [data-modal]"
    )
  );
}

// 4. Use the globally defined loadingStateManager

// 5. Enhanced modal accessibility
document.querySelectorAll(".modal").forEach((modal) => {
  // Store reference to the element that opened the modal
  let previousFocus = null;

  // Get all focusable elements within the modal
  const focusableElements = modal.querySelectorAll(
    'button, [href], input, select, textarea, [tabindex]:not([tabindex="-1"])'
  );

  const firstFocusable = focusableElements[0];
  const lastFocusable = focusableElements[focusableElements.length - 1];

  // Function to open modal with enhanced accessibility
  function openAccessibleModal() {
    // Save current focus position
    previousFocus = document.activeElement;

    // Set ARIA attributes
    modal.setAttribute("aria-hidden", "false");

    // Focus first focusable element
    if (firstFocusable) {
      setTimeout(() => firstFocusable.focus(), 100);
    }

    // Add keydown event listener
    modal.addEventListener("keydown", trapTabKey);
  }

  // Function to close modal with enhanced accessibility
  function closeAccessibleModal() {
    // Reset ARIA attributes
    modal.setAttribute("aria-hidden", "true");

    // Return focus to the element that opened the modal
    if (previousFocus) {
      setTimeout(() => previousFocus.focus(), 100);
    }

    // Remove keydown event listener
    modal.removeEventListener("keydown", trapTabKey);
  }

  // Function to trap tab key inside modal
  function trapTabKey(e) {
    // Trap Tab inside modal
    if (e.key === "Tab") {
      if (e.shiftKey && document.activeElement === firstFocusable) {
        e.preventDefault();
        lastFocusable.focus();
      } else if (!e.shiftKey && document.activeElement === lastFocusable) {
        e.preventDefault();
        firstFocusable.focus();
      }
    }

    // Close on Escape
    if (e.key === "Escape") {
      closeAccessibleModal();
      modal.classList.remove("show");
      setTimeout(() => {
        modal.style.display = "none";
        document.body.style.overflow = "";
      }, 300);
    }
  }

  // Override original modal functions
  const modalId = modal.id;
  const trigger = document.querySelector(`[data-modal="${modalId}"], #signBtn`);

  if (trigger) {
    trigger.addEventListener("click", function (e) {
      openAccessibleModal();
    });
  }

  const closeBtn = modal.querySelector(".close");
  if (closeBtn) {
    closeBtn.addEventListener("click", function () {
      closeAccessibleModal();
    });
  }
});

// The visibilitychange event is already handled in initAdditionalEnhancements

// Define lazyImageObserver at global scope to ensure it's available everywhere
let lazyImageObserver = null;

// Lazy load images with progressive enhancement
if ("loading" in HTMLImageElement.prototype) {
  // Native lazy loading
  document.querySelectorAll(".cont img").forEach((img) => {
    img.loading = "lazy";
  });
} else {
  // Fallback lazy loading with Intersection Observer
  lazyImageObserver = new IntersectionObserver((entries) => {
    entries.forEach((entry) => {
      if (entry.isIntersecting) {
        try {
          const img = entry.target;
          const src = img.getAttribute("data-src");

          if (src) {
            // Add error handling for image loading
            img.addEventListener(
              "error",
              () => {
                console.warn(`Failed to load image: ${src}`);
                img.classList.add("load-error");
                // Add a fallback placeholder or retry logic if needed
              },
              { once: true }
            );

            img.src = src;
          }

          img.classList.add("loaded");
          lazyImageObserver.unobserve(img);
        } catch (error) {
          console.error("Error lazy loading image:", error);
          // Ensure the image is still visible even if loading fails
          entry.target.classList.add("load-error", "loaded");
          lazyImageObserver.unobserve(entry.target);
        }
      }
    });
  }, optimizedObserverOptions);

  document.querySelectorAll(".cont img").forEach((img) => {
    if (!img.getAttribute("data-src")) {
      img.setAttribute("data-src", img.src);
    }
    lazyImageObserver.observe(img);
  });
}

/**
 * Initialize scroll-triggered animations using Intersection Observer
 */
function initScrollAnimations() {
  // We're using the globally defined optimizedObserver already initialized earlier

  // Check if optimizedObserver is available
  if (!optimizedObserver) {
    console.warn("Scroll animation observer not available, applying fallback");
    document.querySelectorAll(".scroll-reveal").forEach((el) => {
      el.classList.add("visible");
    });
    return;
  }

  // Observe all elements with scroll-reveal class with error handling
  document.querySelectorAll(".scroll-reveal").forEach((el) => {
    try {
      // Skip already observed elements
      if (el.hasAttribute("data-observed")) return;

      optimizedObserver.observe(el);
      el.setAttribute("data-observed", "true");
    } catch (error) {
      console.error("Error observing element:", error, el);
      // Ensure element is visible if observation fails
      el.classList.add("visible");
    }
  });
}

/**
 * Initialize touch feedback effects for better mobile experience
 */
function initTouchFeedback() {
  // Add touch-ripple class to interactive elements
  const interactiveElements = document.querySelectorAll(
    ".addToCart, #signBtn, #searchBtn, .signButton, #subscribeButton, button"
  );

  interactiveElements.forEach((element) => {
    if (!element.classList.contains("touch-ripple")) {
      element.classList.add("touch-ripple");
    }

    // Add mousedown/touchstart event for ripple effect with proper cleanup support
    const safeCreateRippleEffect = window.withErrorBoundary(
      createRippleEffect,
      "ripple effect"
    );
    element.addEventListener("mousedown", safeCreateRippleEffect);
    element.addEventListener("touchstart", safeCreateRippleEffect, {
      passive: true,
    });
  });

  function createRippleEffect(event) {
    const button = event.currentTarget;

    // Remove existing ripple elements
    const existingRipple = button.querySelector(".ripple");
    if (existingRipple) {
      existingRipple.remove();
    }

    // Create new ripple element
    const ripple = document.createElement("span");
    ripple.classList.add("ripple");
    button.appendChild(ripple);

    // Position the ripple where the user clicked/touched
    const rect = button.getBoundingClientRect();
    const clientX =
      event.type === "touchstart" ? event.touches[0].clientX : event.clientX;
    const clientY =
      event.type === "touchstart" ? event.touches[0].clientY : event.clientY;

    const x = clientX - rect.left;
    const y = clientY - rect.top;

    ripple.style.left = `${x}px`;
    ripple.style.top = `${y}px`;

    // Remove ripple after animation completes
    setTimeout(() => {
      ripple.remove();
    }, 600);
  }
}

/**
 * Initialize smooth state transitions for UI elements
 */
function initStateTransitions() {
  // Handle modal transitions with error boundaries
  const modalTriggers = document.querySelectorAll("[data-modal]");
  modalTriggers.forEach((trigger) => {
    trigger.addEventListener(
      "click",
      window.withErrorBoundary(function (e) {
        const modalId = this.getAttribute("data-modal");
        const modal = document.getElementById(modalId);

        if (modal) {
          e.preventDefault();
          openModal(modal);
        }
      }, "modal trigger")
    );
  });

  // Close modal buttons with error boundaries
  const closeButtons = document.querySelectorAll(".close");
  closeButtons.forEach((button) => {
    button.addEventListener(
      "click",
      window.withErrorBoundary(function () {
        const modal = this.closest(".modal");
        closeModal(modal);
      }, "modal close")
    );
  });

  // Keep track of modal listeners for cleanup
  window.modalListeners = window.modalListeners || new Map();

  // Add keyboard accessibility for modals with error handling
  document.addEventListener(
    "keydown",
    window.withErrorBoundary(function (e) {
      if (e.key === "Escape") {
        const visibleModal = document.querySelector(".modal.show");
        if (visibleModal) {
          closeModal(visibleModal);
        }
      }
    }, "modal keyboard navigation")
  );

  /**
   * Opens a modal dialog with proper accessibility and transitions
   * @param {HTMLElement} modal - The modal element to open
   */
  function openModal(modal) {
    try {
      // Ensure modal is displayed before applying transitions
      modal.style.display = "block";

      // Trigger reflow to ensure transition works
      modal.offsetHeight;

      // Add show class to trigger transition
      modal.classList.add("show");

      modal.setAttribute("tabindex", "-1");
      modal.focus();

      // Disable scrolling on body
      document.body.style.overflow = "hidden";
    } catch (error) {
      console.error("Error opening modal:", error);
      // Ensure modal is at least visible if transition fails
      if (modal) {
        modal.style.display = "block";
        modal.classList.add("show");
      }
    }

    // Track for cleanup
    // Define trap tab key function to keep focus inside modal
    function trapTabKey(event) {
      if (event.key !== "Tab") return;

      // Get all focusable elements inside modal
      const focusableElements = modal.querySelectorAll(
        'a[href], button, textarea, input, select, [tabindex]:not([tabindex="-1"])'
      );

      if (focusableElements.length === 0) return;

      const firstElement = focusableElements[0];
      const lastElement = focusableElements[focusableElements.length - 1];

      // Handle tab navigation to keep focus inside modal
      if (event.shiftKey && document.activeElement === firstElement) {
        // If shift+tab on first element, move to last element
        event.preventDefault();
        lastElement.focus();
      } else if (!event.shiftKey && document.activeElement === lastElement) {
        // If tab on last element, move to first element
        event.preventDefault();
        firstElement.focus();
      }
    }

    const trapTabKeyHandler = window.withErrorBoundary(
      trapTabKey,
      "tab key trap"
    );

    // Clean up any existing handler before setting a new one
    if (window.modalListeners.has(modal)) {
      const existingHandler = window.modalListeners.get(modal);
      modal.removeEventListener("keydown", existingHandler);
    }

    // Set new handler
    modal.addEventListener("keydown", trapTabKeyHandler);
    window.modalListeners.set(modal, trapTabKeyHandler);
  }

  /**
   * Closes a modal dialog with proper transitions and cleanup
   * @param {HTMLElement} modal - The modal element to close
   */
  function closeModal(modal) {
    // Remove show class to trigger transition
    modal.classList.remove("show");

    // Remove event listener
    if (window.modalListeners.has(modal)) {
      const handler = window.modalListeners.get(modal);
      modal.removeEventListener("keydown", handler);
      window.modalListeners.delete(modal);
    }

    // Wait for transition to finish before hiding
    setTimeout(() => {
      modal.style.display = "none";
      document.body.style.overflow = "";
    }, 300); // Match this with your CSS transition time
  }
}

/**
 * Initialize loading state management
 */
function initLoadingStates() {
  // Target elements that might need loading states
  const productGrid = document.querySelector(".myImages");
  const searchForm = document.querySelector("form");

  // Setup initial loading states function defined early for better organization
  function setupInitialLoadingStates() {
    if (!productGrid) return;

    // Set a shorter timeout for initial page load
    window.toggleLoadingState(productGrid, true, 5000);

    // Use a more efficient approach to detect when images are loaded
    let loadedImages = 0;
    const totalImages = document.querySelectorAll(".myImages img").length;

    const imageLoadHandler = () => {
      loadedImages++;
      if (loadedImages >= totalImages) {
        window.toggleLoadingState(productGrid, false);
      }
    };

    // Track image load listeners for cleanup
    const imageLoadListeners = new Map();

    // Check already loaded images and attach listeners to loading ones
    document.querySelectorAll(".myImages img").forEach((img) => {
      if (img.complete) {
        // Image already loaded
        imageLoadHandler();
      } else {
        // Add event listeners for loading or error with cleanup tracking
        const loadListener = () => imageLoadHandler();
        const errorListener = () => {
          console.warn(
            `Failed to load image: ${img.src || img.getAttribute("data-src")}`
          );
          imageLoadHandler(); // Count error as loaded to prevent blocking
        };

        img.addEventListener("load", loadListener);
        img.addEventListener("error", errorListener);

        // Store listeners for cleanup
        imageLoadListeners.set(img, {
          load: loadListener,
          error: errorListener,
        });
      }
    });

    // Fallback timeout to prevent indefinite loading state
    const fallbackTimeout = setTimeout(() => {
      if (loadedImages < totalImages) {
        console.warn(
          `Some images failed to load (${loadedImages}/${totalImages}), removing loading state`
        );
        window.toggleLoadingState(productGrid, false);

        // Clean up remaining listeners
        imageLoadListeners.forEach((listeners, img) => {
          img.removeEventListener("load", listeners.load);
          img.removeEventListener("error", listeners.error);
        });
        imageLoadListeners.clear();
      }
    }, 5000);

    // Register fallback timeout for cleanup
    cleanupManager.registerTimeout(fallbackTimeout);
  }

  // Add loading state utility functions to window for reuse
  window.toggleLoadingState = function (element, isLoading, timeoutMs = 8000) {
    if (!element) return;

    if (isLoading) {
      // Use the enhanced loading state manager
      loadingStateManager.startLoading(element, timeoutMs);

      // Optional: Create and add a loading spinner with a single reflow
      if (!element.querySelector(".loading")) {
        requestAnimationFrame(() => {
          const spinner = document.createElement("div");
          spinner.classList.add("loading");
          element.appendChild(spinner);
        });
      }
    } else {
      loadingStateManager.stopLoading(element);

      // Remove loading spinner if it exists
      const spinner = element.querySelector(".loading");
      if (spinner) {
        requestAnimationFrame(() => {
          spinner.remove();
        });
      }
    }
  };

  // Call the function to set up initial states
  setupInitialLoadingStates();

  // Initialize animation optimizations
  optimizeAnimationPerformance();

  if (searchForm) {
    const searchHandler = function (e) {
      e.preventDefault(); // Prevent default form submission if handling via AJAX

      // Don't add loading state if already loading
      if (this.classList.contains("loading-state")) return;

      window.toggleLoadingState(this, true, 3000); // Set shorter timeout for search

      try {
        // Your actual search logic would go here

        // Simulate search completion with success feedback
        const searchTimeout = setTimeout(() => {
          window.toggleLoadingState(this, false);

          // Add success feedback with clean transition
          requestAnimationFrame(() => {
            this.classList.add("search-complete");
            setTimeout(() => {
              this.classList.remove("search-complete");
            }, 800);
          });
        }, 1000);

        // Register timeout for cleanup
        cleanupManager.registerTimeout(searchTimeout);
      } catch (error) {
        console.error("Search error:", error);
        window.toggleLoadingState(this, false);

        // Add error feedback
        requestAnimationFrame(() => {
          this.classList.add("search-error");
          setTimeout(() => {
            this.classList.remove("search-error");
          }, 2000);
        });
      }
    };

    // Add event listener with cleanup tracking
    searchForm.addEventListener("submit", searchHandler);
  }
}

/**
 * Initialize cart animations and interactions
 * Manages add to cart button click events, animations, and loading states
 */
function initCartAnimations() {
  // Add to cart loading and animation
  const addToCartButtons = document.querySelectorAll(".addToCart");

  addToCartButtons.forEach((button) => {
    button.addEventListener("click", function (e) {
      e.preventDefault();

      // Prevent multiple clicks
      if (this.classList.contains("processing")) return;

      this.classList.add("processing");

      // Show loading state with reduced timeout for better UX
      window.toggleLoadingState(this, true, 3000);

      try {
        // Simulate cart update (replace with actual cart logic)
        setTimeout(() => {
          this.classList.remove("processing");
          window.toggleLoadingState(this, false);

          // Add success animation with requestAnimationFrame for smoother transitions
          requestAnimationFrame(() => {
            this.classList.add("cart-updated");

            // Use transitionend for more reliable timing
            const removeAnimation = () => {
              this.classList.remove("cart-updated");
              this.removeEventListener("animationend", removeAnimation);
            };

            // Fallback to setTimeout in case animation doesn't complete
            const fallbackTimer = setTimeout(removeAnimation, 800);

            this.addEventListener(
              "animationend",
              () => {
                try {
                  clearTimeout(fallbackTimer);
                  removeAnimation();
                } catch (error) {
                  console.error("Error cleaning up cart animation:", error);
                  // Ensure button returns to normal state
                  this.classList.remove("cart-updated", "processing");
                }
              },
              { once: true }
            ); // Use once option for automatic cleanup
          });
        }, 800);
      } catch (error) {
        console.error("Cart update error:", error);
        this.classList.remove("processing");
        window.toggleLoadingState(this, false);

        // Show error state
        requestAnimationFrame(() => {
          this.classList.add("cart-error");
          setTimeout(() => {
            this.classList.remove("cart-error");
          }, 2000);
        });
      }
    });
  });
}

/**
 * Initialize additional UI enhancements
 */
function initAdditionalEnhancements() {
  // Add CSS class to indicate JavaScript is enabled
  document.documentElement.classList.add("js-enabled");

  // Detect keyboard users for focus styles
  // Add keyboard focus detection for accessibility - use passive listeners for performance
  document.addEventListener(
    "keydown",
    function (e) {
      if (e.key === "Tab") {
        document.body.classList.add("keyboard-user");
      }
    },
    { passive: true }
  );

  document.addEventListener(
    "mousedown",
    function () {
      document.body.classList.remove("keyboard-user");
    },
    { passive: true }
  );

  // Smooth scrolling for anchor links
  document.querySelectorAll('a[href^="#"]').forEach((anchor) => {
    anchor.addEventListener("click", function (e) {
      const targetId = this.getAttribute("href");
      if (targetId !== "#") {
        const targetElement = document.querySelector(targetId);

        if (targetElement) {
          e.preventDefault();
          targetElement.scrollIntoView({
            behavior: "smooth",
            block: "start",
          });
        }
      }
    });
  });

  // Register all observers in one place with proper tracking to avoid duplication
  const observers = [
    { name: "optimizedObserver", ref: optimizedObserver },
    { name: "lazyImageObserver", ref: lazyImageObserver },
    { name: "mutationObserver", ref: mutationObserver },
  ];

  observers.forEach(({ name, ref }) => {
    // Skip null observers (like lazyImageObserver when native lazy loading is used)
    if (!ref) {
      console.debug(`Observer ${name} not available, skipping registration`);
      return;
    }
    try {
      if (ref && !cleanupManager.observers.includes(ref)) {
        cleanupManager.registerObserver(ref);
        console.debug(`Registered ${name} for cleanup`);
      }
    } catch (error) {
      console.error(`Failed to register ${name}:`, error);
    }
  });

  // Re-register performance monitor for cleanup (just to be safe)
  cleanupManager.registerPerformanceMonitor();

  // Clean up before page unload and when page becomes invisible
  window.addEventListener("beforeunload", () => {
    cleanupManager.cleanup();
  });

  // Ensure we have only one visibility change handler
  document.addEventListener("visibilitychange", () => {
    if (document.visibilityState === "hidden") {
      // Clean up all observers and timeouts
      cleanupManager.cleanup();
    } else if (document.visibilityState === "visible") {
      // Restart performance monitoring when the page becomes visible again
      try {
        if (window.performanceMonitor) {
          window.performanceMonitor.start();
        }
        // Re-initialize necessary observers
        initScrollAnimations();
      } catch (error) {
        console.warn(
          "Error restoring page state after visibility change:",
          error
        );
      }
    }
  });
}
