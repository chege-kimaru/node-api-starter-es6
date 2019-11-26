'use strict';
module.exports = (sequelize, DataTypes) => {
    const UserVerificationToken = sequelize.define('UserVerificationToken', {
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
        expiry: {type: DataTypes.DATE, allowNull: false}
    }, {
        underscored: true,
    });
    UserVerificationToken.associate = function (models) {
        // associations can be defined here
        UserVerificationToken.belongsTo(models.User, {
            foreignKey: 'user_id'
        });
    };
    return UserVerificationToken;
};
