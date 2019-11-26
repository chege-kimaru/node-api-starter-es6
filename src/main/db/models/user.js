'use strict';
module.exports = (sequelize, DataTypes) => {
    const User = sequelize.define('User', {
        id: {
            allowNull: false,
            primaryKey: true,
            type: DataTypes.UUID,
            defaultValue: DataTypes.UUIDV4
        },
        username: {
            type: DataTypes.STRING,
            unique: true
        },
        email: {
            type: DataTypes.STRING,
            unique: true,
            allowNull: false
        },
        password: {
            type: DataTypes.STRING,
            allowNull: false
        },
        role: {
            type: DataTypes.INTEGER,
            allowNull: false,
            defaultValue: 1
        },
        signup_type: {
            type: DataTypes.INTEGER,
            defaultValue: 0,
            allowNull: false
        },
        verified: {
            type: DataTypes.BOOLEAN,
            defaultValue: false,
            allowNull:false
        },
    }, {
        underscored: true,
        // defaultScope: {
        //     attributes: {exclude: ['password']}
        // }
    });
    User.associate = function (models) {
        // associations can be defined here
        User.hasOne(models.UserVerificationToken, {
            foreignKey: 'user_id'
        });
        User.hasOne(models.ForgotPasswordToken, {
            foreignKey: 'user_id'
        });
    };
    return User;
};
