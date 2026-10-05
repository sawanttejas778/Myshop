import numpy as np
import pandas as pd
from scipy.stats import weibull_min, expon

# ------------------------------
# Parameters
# ------------------------------
n_total = 10000           # total sample size
np.random.seed(42)        # reproducibility

# Baseline Weibull parameters
lambda_ = 0.1             # scale
nu = 1.5                  # shape (increasing hazard)

# Coefficients for log-hazard (Cox PH)
beta_age = 0.03
beta_gender = 0.2         # male higher risk
beta_treatment = -0.5     # treatment reduces risk
beta_biomarker = 0.15
beta_stage = [0.0, 0.3, 0.6, 1.0]  # stage I,II,III,IV

# Censoring parameters
admin_censoring_time = 5.0   # years
random_censoring_rate = 0.05 # exponential rate

# ------------------------------
# Generate covariates with stratification
# ------------------------------
# Ensure balance across gender, treatment, and stage
gender_vals = [0, 1]
treatment_vals = [0, 1]
stage_vals = [1, 2, 3, 4]

# Number of samples per stratum (at least 50, adjust to total)
n_strata = max(50, n_total // (len(gender_vals)*len(treatment_vals)*len(stage_vals)))
# but we need exact total; we'll oversample then sample down
strata_counts = []
for g in gender_vals:
    for t in treatment_vals:
        for s in stage_vals:
            strata_counts.append(n_strata)

# Create stratified dataframe
dfs = []
for (g, t, s), n in zip([(g,t,s) for g in gender_vals for t in treatment_vals for s in stage_vals], strata_counts):
    df_stratum = pd.DataFrame({
        'gender': [g]*n,
        'treatment': [t]*n,
        'stage': [s]*n,
    })
    dfs.append(df_stratum)

df = pd.concat(dfs, ignore_index=True)

# Now add continuous covariates with some correlation
n = len(df)
df['age'] = np.random.normal(loc=60, scale=10, size=n).clip(30, 80)
df['biomarker'] = np.random.normal(loc=5, scale=2, size=n).clip(0, 10)

# Add some noise to make covariates not perfectly independent (optional)
df['age'] += np.random.normal(0, 1, n)
df['biomarker'] += np.random.normal(0, 0.5, n)

# ------------------------------
# Generate survival times from Weibull PH
# ------------------------------
# Linear predictor
lp = (beta_age * (df['age'] - 50) +           # center age
      beta_gender * df['gender'] +
      beta_treatment * df['treatment'] +
      beta_biomarker * (df['biomarker'] - 5) + # center biomarker
      df['stage'].apply(lambda s: beta_stage[s-1]))

# Scale parameter per individual: lambda_i = lambda_ * exp(lp)
scale_i = lambda_ * np.exp(lp)

# Weibull survival times (event times)
# Using inverse CDF: T = (-log(U) / (lambda_i * exp(lp)))^{1/nu} ? Actually we need the correct parameterization.
# For Weibull with scale lambda and shape nu, hazard = lambda*nu*t^{nu-1}? 
# We'll use the standard scipy parameterization: Weibull with shape nu and scale = 1/lambda? 
# Better: We use the relationship that if T ~ Weibull(shape=nu, scale=1/lambda), then survival S(t)=exp(-(lambda*t)^nu).
# So we can sample U~Uniform(0,1), then T = ( -log(U) / (lambda * exp(lp)) )^{1/nu}? Actually S(t)=exp(-(lambda*t)^nu * exp(lp)? Wait.
# The standard Cox PH with Weibull baseline: hazard h(t|X)=h0(t)*exp(lp) with h0(t)=lambda*nu*t^{nu-1}.
# Then baseline survival S0(t)=exp(-lambda*t^nu). So S(t|X)=S0(t)^{exp(lp)} = exp(-lambda*t^nu * exp(lp)).
# So to sample, set U~Uniform(0,1), U = exp(-lambda*T^nu*exp(lp)) => -log(U) = lambda*T^nu*exp(lp) => T = ( -log(U) / (lambda*exp(lp)) )^{1/nu}
# Yes.

U = np.random.uniform(0, 1, n)
T_event = ( -np.log(U) / (lambda_ * np.exp(lp)) ) ** (1/nu)

# ------------------------------
# Apply censoring
# ------------------------------
# Random censoring times (exponential)
T_cens_random = np.random.exponential(scale=1/random_censoring_rate, size=n)

# Administrative censoring at fixed time
T_cens_admin = admin_censoring_time

# Observed time is min of event, random censoring, admin
T_cens = np.minimum(T_cens_random, T_cens_admin)
observed_time = np.minimum(T_event, T_cens)
event = (T_event <= T_cens).astype(int)

df['time'] = observed_time
df['event'] = event

# Optionally, add an ID column
df.insert(0, 'id', range(1, n+1))

# ------------------------------
# Shuffle rows (random order)
# ------------------------------
df = df.sample(frac=1, random_state=42).reset_index(drop=True)

# ------------------------------
# Save to CSV
# ------------------------------
df.to_csv('survival_dataset.csv', index=False)
print("Dataset saved to 'survival_dataset.csv'")
print(f"Event rate: {event.mean():.2%}")
print("Columns:", df.columns.tolist())
print(df.head())