'use strict';
module.exports = (sequelize, DataTypes) => {
  const ForgotPasswordToken = sequelize.define('ForgotPasswordToken', {
    id: {
      allowNull: false,
      primaryKey: true,
      type: DataTypes.UUID,
      defaultValue: DataTypes.UUIDV4
    },
    token: {type: DataTypes.STRING, allowNull: false},
    user_id: {
      type: DataTypes.UUID,
      unique: true,
      allowNull: false,
      onDelete: 'RESTRICT',
      onUpdate: 'RESTRICT',
      references: {
        model: 'users',
        key: 'id'
      }
    },
    expiry: {type: DataTypes.DATE, allowNull: false},
    used: {
      type: DataTypes.BOOLEAN,
      allowNull: false,
      defaultValue: false
    }
  }, {
    underscored: true,
  });
  ForgotPasswordToken.associate = function(models) {
    // associations can be defined here
    ForgotPasswordToken.belongsTo(models.User, {
      foreignKey: 'user_id'
    });
  };
  return ForgotPasswordToken;
};
