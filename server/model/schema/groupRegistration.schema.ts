import { Schema, Document, Types } from 'mongoose';

interface IGroupRegistration extends Document {
  groupId: Types.ObjectId;
  userId: Types.ObjectId;
}

const GroupRegistrationSchema = new Schema<IGroupRegistration>(
  {
    groupId: {
      type: Schema.Types.ObjectId,
      ref: 'Group',
      required: [true, 'Please provide a group ID'],
    },
    userId: {
      type: Schema.Types.ObjectId,
      ref: 'User',
      required: [true, 'Please provide a user ID'],
    }
  },
  {
    timestamps: true,
  }
);

// Create compound index to ensure a user can only register for a group once
GroupRegistrationSchema.index({ groupId: 1, userId: 1 }, { unique: true });

export { IGroupRegistration, GroupRegistrationSchema };
