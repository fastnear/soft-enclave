/**
 * Enclave Base - Abstract Interface
 *
 * Defines the common interface for all enclave backends (worker, iframe, etc.)
 * All backends must implement this interface to ensure consistent API surface.
 *
 * Design Goals:
 * - Unified API across different isolation mechanisms
 * - Protocol-agnostic (supports simple, advanced, HPKE)
 * - Metrics collection for security monitoring
 * - Lifecycle management (initialization, execution, cleanup)
 */

/**
 * Abstract base class for enclave backends
 *
 * Subclasses must implement:
 * - _performInitialization()
 * - _performExecution(code, context, options)
 * - _performCleanup()
 *
 * Optional overrides:
 * - _validateOptions(options)
 * - _computeMetrics(executionResult)
 */
export class EnclaveBase {
  constructor(options = {}) {
    if (new.target === EnclaveBase) {
      throw new Error('EnclaveBase is abstract and cannot be instantiated directly');
    }

    this.options = this._validateOptions(options);
    this.initialized = false;
    this.metrics = {
      operationsCount: 0,
      averageKeyExposureMs: 0,
      totalKeyExposureMsSum: 0,
      maxKeyExposureMs: 0
    };

    // Protocol configuration
    this.protocol = options.protocol || 'advanced'; // 'simple', 'advanced', 'hpke'
    this.mode = this.constructor.MODE; // Set by subclass
  }

  /**
   * Initialize the enclave
   *
   * This is the public API method that handles common initialization logic
   * and delegates backend-specific work to _performInitialization().
   *
   * @returns {Promise<void>}
   */
  async initialize() {
    if (this.initialized) {
      throw new Error('Enclave already initialized');
    }

    console.log(`[Enclave/${this.mode}] Initializing with protocol=${this.protocol}...`);
    const startTime = performance.now();

    await this._performInitialization();

    this.initialized = true;
    const duration = performance.now() - startTime;
    console.log(`[Enclave/${this.mode}] Initialization complete in ${duration.toFixed(2)}ms`);
  }

  /**
   * Execute code in the enclave
   *
   * @param {string} code - JavaScript code to execute
   * @param {object} context - Execution context (variables available to code)
   * @param {object} options - Execution options (timeout, etc.)
   * @returns {Promise<{result: any, metrics: object, totalDurationMs: number}>}
   */
  async execute(code, context = {}, options = {}) {
    this._ensureInitialized();

    console.log(`[Enclave/${this.mode}] Executing code...`);
    const startTime = performance.now();

    const result = await this._performExecution(code, context, options);

    const totalDuration = performance.now() - startTime;

    // Compute and update metrics
    const executionMetrics = this._computeMetrics(result);
    this._updateMetrics(executionMetrics);

    console.log(`[Enclave/${this.mode}] Execution complete in ${totalDuration.toFixed(2)}ms`);
    if (executionMetrics.keyExposureMs !== undefined) {
      console.log(`[Enclave/${this.mode}] Key exposure: ${executionMetrics.keyExposureMs.toFixed(2)}ms`);
    }

    return {
      result: result.result,
      metrics: executionMetrics,
      totalDurationMs: totalDuration
    };
  }

  /**
   * Get current metrics
   *
   * @returns {object} Current metrics snapshot
   */
  getMetrics() {
    return {
      ...this.metrics,
      mode: this.mode,
      protocol: this.protocol,
      averageKeyExposureMs: this.metrics.operationsCount > 0
        ? this.metrics.totalKeyExposureMsSum / this.metrics.operationsCount
        : 0
    };
  }

  /**
   * Clean up resources
   *
   * @returns {Promise<void>}
   */
  async destroy() {
    if (!this.initialized) {
      return;
    }

    console.log(`[Enclave/${this.mode}] Cleaning up...`);

    await this._performCleanup();

    this.initialized = false;
    console.log(`[Enclave/${this.mode}] Cleanup complete`);
  }

  /**
   * Check if enclave is initialized
   *
   * @returns {boolean}
   */
  isInitialized() {
    return this.initialized;
  }

  // ========================================================================
  // Protected methods (to be implemented by subclasses)
  // ========================================================================

  /**
   * Validate and normalize options
   *
   * Subclasses can override to add backend-specific validation
   *
   * @param {object} options - Raw options
   * @returns {object} Validated options
   * @protected
   */
  _validateOptions(options) {
    return {
      protocol: options.protocol || 'advanced',
      timeout: options.timeout || 30000,
      ...options
    };
  }

  /**
   * Perform backend-specific initialization
   *
   * Must be implemented by subclass
   *
   * @returns {Promise<void>}
   * @protected
   * @abstract
   */
  async _performInitialization() {
    throw new Error('_performInitialization() must be implemented by subclass');
  }

  /**
   * Perform backend-specific code execution
   *
   * Must be implemented by subclass
   *
   * @param {string} code - JavaScript code
   * @param {object} context - Execution context
   * @param {object} options - Execution options
   * @returns {Promise<object>} Result with metrics
   * @protected
   * @abstract
   */
  async _performExecution(code, context, options) {
    throw new Error('_performExecution() must be implemented by subclass');
  }

  /**
   * Perform backend-specific cleanup
   *
   * Must be implemented by subclass
   *
   * @returns {Promise<void>}
   * @protected
   * @abstract
   */
  async _performCleanup() {
    throw new Error('_performCleanup() must be implemented by subclass');
  }

  /**
   * Compute metrics from execution result
   *
   * Subclasses can override to extract backend-specific metrics
   *
   * @param {object} result - Execution result
   * @returns {object} Metrics
   * @protected
   */
  _computeMetrics(result) {
    return result.metrics || {
      keyExposureMs: 0
    };
  }

  /**
   * Update metrics with execution data
   *
   * @param {object} executionMetrics - Metrics from execution
   * @protected
   */
  _updateMetrics(executionMetrics) {
    this.metrics.operationsCount++;

    if (executionMetrics.keyExposureMs !== undefined) {
      this.metrics.totalKeyExposureMsSum += executionMetrics.keyExposureMs;
      this.metrics.maxKeyExposureMs = Math.max(
        this.metrics.maxKeyExposureMs,
        executionMetrics.keyExposureMs
      );
    }
  }

  /**
   * Ensure enclave is initialized
   *
   * @protected
   */
  _ensureInitialized() {
    if (!this.initialized) {
      throw new Error('Enclave not initialized. Call initialize() first.');
    }
  }
}
