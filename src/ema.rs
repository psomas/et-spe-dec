/// A struct to hold the state of the Exponential Moving Average (EMA) calculation.
#[derive(Debug, Clone, Copy)]
pub struct ExponentialMovingAverage {
    /// The current calculated EMA value.
    current_ema: f64,
    /// The smoothing factor (alpha) used in the EMA calculation.
    /// It's calculated as 2 / (period + 1).
    alpha: f64,
    /// A flag to indicate if this is the first data point,
    /// in which case the EMA is initialized directly.
    is_initialized: bool,
}

impl ExponentialMovingAverage {
    /// Creates a new `ExponentialMovingAverage` instance.
    ///
    /// # Arguments
    ///
    /// * `period` - The number of periods to consider for the EMA calculation.
    ///              A larger period makes the EMA smoother and less responsive to price changes.
    ///              Must be greater than 0.
    ///
    /// # Panics
    ///
    /// Panics if `period` is less than or equal to 0.
    pub fn new(period: u32) -> Self {
        if period == 0 {
            panic!("Period must be greater than 0 for EMA calculation.");
        }
        let alpha = 2.0 / (period as f64 + 1.0);
        ExponentialMovingAverage {
            current_ema: 0.0, // Will be initialized with the first data point
            alpha,
            is_initialized: false,
        }
    }

    /// Updates the EMA with a new data point and returns the new EMA value.
    ///
    /// The first data point directly initializes the `current_ema`.
    /// Subsequent data points update the `current_ema` using the EMA formula:
    ///
    /// EMA = (current_data_point * alpha) + (previous_ema * (1 - alpha))
    ///
    /// # Arguments
    ///
    /// * `data_point` - The new data point to incorporate into the EMA.
    ///
    /// # Returns
    ///
    /// The newly calculated Exponential Moving Average.
    pub fn update(&mut self, data_point: f64) -> f64 {
        if !self.is_initialized {
            self.current_ema = data_point;
            self.is_initialized = true;
        } else {
            self.current_ema = (data_point * self.alpha) + (self.current_ema * (1.0 - self.alpha));
        }
        self.current_ema
    }

    /// Returns the current EMA value without updating it.
    pub fn current_ema(&self) -> f64 {
        self.current_ema
    }

    /// Returns the smoothing factor (alpha) used in the EMA calculation.
    pub fn alpha(&self) -> f64 {
        self.alpha
    }
}
