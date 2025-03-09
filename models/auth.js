import { mongoose } from "mongoose";

const AuthSchema = new mongoose.Schema({
  id: {
    type: String,
    require: true,
    unique: true,
  },
  name: {
    type: String,
    require: true,
  },
  email: {
    type: String,
    require: true,
    unique: true,
  },
  password: {
    type: String,
    require: true,
  },
});

export const AuthModel = mongoose.model("auth", AuthSchema);
