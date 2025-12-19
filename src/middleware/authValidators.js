import * as yup from "yup";

export const signUpValidation = async (req, res, next) => {
  const schema = yup.object({
    username: yup
      .string()
      .required("Username is required")
      .min(3, "Username must be at least 3 characters"),
    email: yup
      .string()
      .email("Invalid email format")
      .required("Email is required"),
    password: yup
      .string()
      .required("Password is required")
      .min(6, "Password must be at least 6 characters")
      .matches(
        /^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)/,
        "Password must contain uppercase, lowercase, and number"
      )
  });

  try {
    await schema.validate(req.body, { abortEarly: false });
    next();
  } catch (error) {
    return res.status(400).json({
      error: "Validation failed",
      details: error.errors
    });
  }
};

export const signInValidation = async (req, res, next) => {
  const schema = yup.object({
    email: yup.string().email().required("Email is required"),
    password: yup.string().required("Password is required")
  });

  try {
    await schema.validate(req.body, { abortEarly: false });
    next();
  } catch (error) {
    return res.status(400).json({
      error: "Validation failed",
      details: error.errors
    });
  }
};

export const changePasswordValidation = async (req, res, next) => {
  const schema = yup.object({
    
  })
}