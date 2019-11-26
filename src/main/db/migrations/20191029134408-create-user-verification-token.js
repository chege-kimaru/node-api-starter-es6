'use strict';
module.exports = {
    up: (queryInterface, Sequelize) => {
        return queryInterface.createTable('user_verification_tokens', {
            id: {
                allowNull: false,
                primaryKey: true,
                type: Sequelize.UUID,
                defaultValue: Sequelize.UUIDV4
            },
            token: {
                type: Sequelize.STRING,
                allowNull: false
            },
            user_id: {
                type: Sequelize.UUID,
                unique: true,
                allowNull: false,
                onDelete: 'RESTRICT',
                onUpdate: 'RESTRICT',
                references: {
                    model: 'users',
                    key: 'id'
                }
            },
            expiry: {
                type: Sequelize.DATE,
                allowNull: false
            },
            created_at: {
                allowNull: false,
                type: Sequelize.DATE
            },
            updated_at: {
                allowNull: false,
                type: Sequelize.DATE
            }
        });
    },
    down: (queryInterface, Sequelize) => {
        return queryInterface.dropTable('user_verification_tokens');
    }
};
